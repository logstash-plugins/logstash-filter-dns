require "resolv"

# ref: https://github.com/logstash-plugins/logstash-filter-dns/issues/40
#
# JRuby 9k versions prior to 9.1.16.0 have a bug which crashes IP address
# resolution after 64k unique IP addresses resolutions.
#
# Note that the oldest JRuby version in LS 6 is 9.1.13.0 and
# JRuby 1.7.25 and 1.7.27 (the 2 versions used across LS 5) are not affected by this bug.
#
# The code below is copied from JRuby 9.1.16.0 resolv.rb:
# https://github.com/jruby/jruby/blob/9.1.16.0/lib/ruby/stdlib/resolv.rb#L775-L784

JRUBY_GEM_VERSION = Gem::Version.new(JRUBY_VERSION)

if JRUBY_GEM_VERSION >= Gem::Version.new("9.1.13.0") && JRUBY_GEM_VERSION < Gem::Version.new("9.1.16.0")
  class Resolv
    class DNS
      class Requester
        class UnconnectedUDP
          def sender(msg, data, host, port=Port)
            sock = @socks_hash[host.index(':') ? "::" : "0.0.0.0"]
            return nil if !sock
            service = [IPAddr.new(host), port]
            id = DNS.allocate_request_id(service[0], service[1])
            request = msg.encode
            request[0,2] = [id].pack('n')
            return @senders[[service, id]] =
                Sender.new(request, data, sock, host, port)
          end
        end
      end
    end
  end
end