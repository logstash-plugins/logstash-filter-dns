# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "lru_redux"
require "resolv"
require "logstash/filters/dns/resolv_patch"

java_import 'java.net.IDN'


# The DNS filter performs a lookup (either an A record/CNAME record lookup
# or a reverse lookup at the PTR record) on records specified under the
# `reverse` arrays or respectively under the `resolve` arrays.
#
# The config should look like this:
# [source,ruby]
#     filter {
#       dns {
#         reverse => [ "source_host", "field_with_address" ]
#         resolve => [ "field_with_fqdn" ]
#         action => "replace"
#       }
#     }
#
# This filter, like all filters, only processes 1 event at a time, so the use
# of this plugin can significantly slow down your pipeline's throughput if you
# have a high latency network. By way of example, if each DNS lookup takes 2
# milliseconds, the maximum throughput you can achieve with a single filter
# worker is 500 events per second (1000 milliseconds / 2 milliseconds).
class LogStash::Filters::DNS < LogStash::Filters::Base
  # TODO(sissel): make `action` required? This was always the intent, but it
  # due to a typo it was never enforced. Thus the default behavior in past
  # versions was `append` by accident.

  config_name "dns"

  # Reverse resolve one or more fields.
  config :reverse, :validate => :array

  # Forward resolve one or more fields.
  config :resolve, :validate => :array

  # Determine what action to do: append or replace the values in the fields
  # specified under `reverse` and `resolve`.
  config :action, :validate => [ "append", "replace" ], :default => "append"

  # Use custom nameserver(s). For example:
  #    filter {
  #      dns {
  #         nameserver => {
  #          address => ["8.8.8.8", "8.8.4.4"]
  #          search  => ["internal.net"]
  #        }
  #      }
  #    }
  #
  # nameserver is a hash with the following key:
  #   * a required `address` key, whose value is either a <<string,string>> or an <<array,array>>, representing one or more nameserver ip addresses
  #   * an optional `search` key, whose value is either a <<string,string>> or an <<array,array>>, representing between one and six search domains (e.g., with search domain `com`, a query for `example` will match DNS entries for `example.com`)
  #   * an optional `ndots` key, used in conjunction with `search`, whose value is a <<number,number>>, representing the minimum number of dots in a domain name being resolved that will _prevent_ the search domains from being used (default `1`; this option is rarely needed)
  #   * For backward-compatibility, string ans arrays values are also accepted, representing one or more nameserver ip addresses _without_ search domains.
  #
  # If `nameserver` is not specified then `/etc/resolv.conf` will be read to
  # configure the resolver using the `nameserver`, `domain`,
  # `search` and `ndots` directives in `/etc/resolv.conf`.
  config :nameserver, :validate => :array

  # `resolv` calls will be wrapped in a timeout instance
  config :timeout, :validate => :number, :default => 0.5

  # number of times to retry a failed resolve/reverse
  config :max_retries, :validate => :number, :default => 2

  # set the size of cache for successful requests
  config :hit_cache_size, :validate => :number, :default => 0

  # how long to cache successful requests (in seconds)
  config :hit_cache_ttl, :validate => :number, :default => 60

  # cache size for failed requests
  config :failed_cache_size, :validate => :number, :default => 0

  # how long to cache failed requests (in seconds)
  config :failed_cache_ttl, :validate => :number, :default => 5

  # Use custom hosts file(s). For example: `["/var/db/my_custom_hosts"]`
  config :hostsfile, :validate => :array

  # Tag(s) to apply if a DNS lookup times out. Defaults to `["_dnstimeout"]`.
  config :tag_on_timeout, :validate => :string, :list => true, :default => ["_dnstimeout"]

  attr_reader :hit_cache
  attr_reader :failed_cache

  public
  def register
    if @nameserver.nil? && @hostsfile.nil?
      @resolv = Resolv.new(default_resolvers)
    else
      @resolv = Resolv.new(build_resolvers)
    end

    if @hit_cache_size > 0
      @hit_cache = LruRedux::TTL::ThreadSafeCache.new(@hit_cache_size, @hit_cache_ttl)
    end

    if @failed_cache_size > 0
      @failed_cache = LruRedux::TTL::ThreadSafeCache.new(@failed_cache_size, @failed_cache_ttl)
    end

    @ip_validator = Resolv::AddressRegex
  end # def register

  public
  def filter(event)
    if @resolve
      return if resolve(event).nil?
    end

    if @reverse
      return if reverse(event).nil?
    end

    filter_matched(event)
  end

  private

  def default_resolvers
    [::Resolv::Hosts.new, default_dns_resolver]
  end

  def default_dns_resolver
    dns_resolver(nil)
  end

  def dns_resolver(args=nil)
    dns_resolver = ::Resolv::DNS.new(args)
    dns_resolver.timeouts = @timeout
    dns_resolver
  end

  def build_resolvers
    build_user_host_resolvers.concat([::Resolv::Hosts.new]).concat(build_user_dns_resolver)
  end

  def build_user_host_resolvers
    return [] if @hostsfile.nil? || @hostsfile.empty?
    @hostsfile.map{|fn| ::Resolv::Hosts.new(fn)}
  end

  def build_user_dns_resolver
    return [] if @nameserver.nil? || @nameserver.empty?
    [dns_resolver(normalised_nameserver)]
  end

  def normalised_nameserver
    nameserver_hash = @nameserver.kind_of?(Hash) ? @nameserver.dup : { 'address' => @nameserver }

    nameserver = nameserver_hash.delete('address') || fail(LogStash::ConfigurationError, "DNS Filter: `nameserver` hash must include `address` (got `#{@nameserver}`)")
    nameserver = Array(nameserver).map(&:to_s)
    nameserver.empty? && fail(LogStash::ConfigurationError, "DNS Filter: `nameserver` addresses, when specified, cannot be empty (got `#{@nameserver}`)")

    search     = nameserver_hash.delete('search') || []
    search     = Array(search).map(&:to_s)
    search.size > 6 && fail(LogStash::ConfigurationError, "DNS Filter: A maximum of 6 `search` domains are accepted (got `#{@nameserver}`)")

    ndots      = nameserver_hash.delete('ndots') || 1
    ndots      = Integer(ndots)
    ndots <= 0 && fail(LogStash::ConfigurationError, "DNS Filter: `ndots` must be positive (got `#{@nameserver}`)")

    fail(LogStash::ConfigurationError, "Unknown `nameserver` argument(s): #{nameserver_hash}") unless nameserver_hash.empty?

    {
      :nameserver => nameserver,
      :search     => search,
      :ndots      => ndots
    }
  end

  def resolve(event)
    @resolve.each do |field|
      is_array = false
      raw = event.get(field)

      if raw.nil?
        @logger.warn("DNS filter could not resolve missing field", :field => field)
        next
      end

      if raw.is_a?(Array)
        is_array = true
        if raw.length > 1
          @logger.warn("DNS: skipping resolve, can't deal with multiple values", :field => field, :value => raw)
          return
        end
        raw = raw.first
      end

      if !raw.kind_of?(String)
        @logger.warn("DNS: skipping resolve, can't deal with non-string values", :field => field, :value => raw)
        return
      end

      begin
        return if @failed_cache && @failed_cache[raw] # recently failed resolv, skip
        if @hit_cache
          address = @hit_cache[raw]
          if address.nil?
            if address = retriable_getaddress(raw)
              @hit_cache[raw] = address
            end
          end
        else
          address = retriable_getaddress(raw)
        end
        if address.nil?
          @failed_cache[raw] = true if @failed_cache
          @logger.debug("DNS: couldn't resolve the hostname.",
                        :field => field, :value => raw)
          return
        end
      rescue Resolv::ResolvTimeout
        @failed_cache[raw] = true if @failed_cache
        @logger.debug("DNS: timeout on resolving the hostname.",
                      :field => field, :value => raw)
        @tag_on_timeout.each { |tag| event.tag(tag) }
        return
      rescue SocketError => e
        @logger.error("DNS: Encountered SocketError.",
                      :field => field, :value => raw, :message => e.message)
        return
      rescue Java::JavaLang::IllegalArgumentException => e
        @logger.error("DNS: Unable to parse address.",
                      :field => field, :value => raw, :message => e.message)
        return
      rescue => e
        @logger.error("DNS: Unexpected Error.",
                      :field => field, :value => raw, :message => e.message)
        return
      end

      if @action == "replace"
        if is_array
          event.set(field, [address])
        else
          event.set(field, address)
        end
      else
        if !is_array
          event.set(field, [event.get(field), address])
        else
          arr = event.get(field)
          arr << address
          event.set(field, arr)
        end
      end

    end
  end

  private
  def reverse(event)
    @reverse.each do |field|
      raw = event.get(field)

      if raw.nil?
        @logger.warn("DNS filter could not perform reverse lookup on missing field", :field => field)
        next
      end

      is_array = false
      if raw.is_a?(Array)
          is_array = true
          if raw.length > 1
            @logger.warn("DNS: skipping reverse, can't deal with multiple values", :field => field, :value => raw)
            return
          end
          raw = raw.first
      end
      
      if !raw.kind_of?(String)
        @logger.warn("DNS: skipping reverse, can't deal with non-string values", :field => field, :value => raw)
        return
      end

      if ! @ip_validator.match(raw)
        @logger.debug("DNS: not an address",
                      :field => field, :value => event.get(field))
        return
      end
      begin
        return if @failed_cache && @failed_cache.key?(raw) # recently failed resolv, skip
        if @hit_cache
          hostname = @hit_cache[raw]
          if hostname.nil?
            if hostname = retriable_getname(raw)
              @hit_cache[raw] = hostname
            end
          end
        else
          hostname = retriable_getname(raw)
        end
        if hostname.nil?
          @failed_cache[raw] = true if @failed_cache
          @logger.debug("DNS: couldn't resolve the address.",
                        :field => field, :value => raw)
          return
        end
      rescue Resolv::ResolvTimeout
        @failed_cache[raw] = true if @failed_cache
        @logger.debug("DNS: timeout on resolving address.",
                      :field => field, :value => raw)
        @tag_on_timeout.each { |tag| event.tag(tag) }
        return
      rescue SocketError => e
        @logger.error("DNS: Encountered SocketError.",
                      :field => field, :value => raw, :message => e.message)
        return
      rescue Java::JavaLang::IllegalArgumentException => e
        @logger.error("DNS: Unable to parse address.",
                      :field => field, :value => raw, :message => e.message)
        return
      rescue => e
        @logger.error("DNS: Unexpected Error.",
                      :field => field, :value => raw, :message => e.message)
        return
      end

      if @action == "replace"
        if is_array
          event.set(field, [hostname])
        else
          event.set(field, hostname)
        end
      else
        if !is_array
          event.set(field, [event.get(field), hostname])
        else
          arr = event.get(field)
          arr << hostname
          event.set(field, arr)
        end
      end
    end
  end

  private
  def retriable_request(&block)
    tries = 0
    begin
      block.call
    rescue Resolv::ResolvTimeout, SocketError
      if tries < @max_retries
        tries = tries + 1
        retry
      else
        raise
      end
    end
  end

  private
  def retriable_getname(address)
    retriable_request do
      getname(address)
    end
  end

  private
  def retriable_getaddress(name)
    retriable_request do
      getaddress(name)
    end
  end

  private
  def getname(address)
    name = resolv_getname_or_nil(@resolv, address)
    name && name.force_encoding(Encoding::UTF_8)
    name && IDN.toUnicode(name)
  end

  private
  def getaddress(name)
    idn = IDN.toASCII(name)
    address = resolv_getaddress_or_nil(@resolv, idn)
    address && address.force_encoding(Encoding::UTF_8)
  end

  private
  def resolv_getname_or_nil(resolver, address)
    # `Resolv#each_name` yields to the provided block zero or more times;
    # to prevent it from yielding multiple times when more than one match
    # is found, we return directly in the block.
    # See also `Resolv#getname`
    resolver.each_name(address) do |name|
      return name
    end

    # If no match was found, we return nil.
    return nil
  end

  private
  def resolv_getaddress_or_nil(resolver, name)
    # `Resolv#each_address` yields to the provided block zero or more times;
    # to prevent it from yielding multiple times when more than one match
    # is found, we return directly in the block.
    # See also `Resolv#getaddress`
    resolver.each_address(name) do |address|
      return address
    end

    # If no match was found, we return nil.
    return nil
  end
end # class LogStash::Filters::DNS
