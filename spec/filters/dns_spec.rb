# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/dns"
require "resolv"

describe LogStash::Filters::DNS do
  describe "with stubbed Resolv" do
    before(:each) do
      allow_any_instance_of(Resolv).to receive(:getaddress).with("carrera.databits.net").and_return("199.192.228.250")
      allow_any_instance_of(Resolv).to receive(:getaddress).with("does.not.exist").and_raise(Resolv::ResolvError)
      allow_any_instance_of(Resolv).to receive(:getaddress).with("nonexistanthostname###.net").and_raise(Resolv::ResolvError)
      allow_any_instance_of(Resolv).to receive(:getname).with("199.192.228.250").and_return("carrera.databits.net")
      allow_any_instance_of(Resolv).to receive(:getname).with("127.0.0.1").and_return("localhost")
      allow_any_instance_of(Resolv).to receive(:getname).with("128.0.0.1").and_raise(Resolv::ResolvError)
      allow_any_instance_of(Resolv).to receive(:getname).with("199.192.228.250").and_return("carrera.databits.net")
    end

    describe "dns reverse lookup, replace (on a field)" do
      config <<-CONFIG
        filter {
          dns {
            reverse => "foo"
            action => "replace"
          }
        }
      CONFIG

      sample("foo" => "199.192.228.250") do
        insist { subject.get("foo") } == "carrera.databits.net"
      end
    end

    describe "dns reverse lookup, missing field" do
      let(:plugin) { ::LogStash::Filters::DNS.new("reverse" => "foo") }
      let(:event) { ::LogStash::Event.new }

      before do
        plugin.register
        allow(plugin.logger).to receive(:warn).with(any_args)
      end

      it "should not throw an error when filtering" do
        expect do
          plugin.filter(event)
        end.not_to raise_error
      end

      it "should log a warning" do
        plugin.filter(event)
        expect(plugin.logger).to have_received(:warn).with("DNS filter could not perform reverse lookup on missing field", :field => "foo")
      end
    end

    describe "dns reverse lookup, append" do
      config <<-CONFIG
        filter {
          dns {
            reverse => "foo"
            action => "append"
          }
        }
      CONFIG

      sample("foo" => "199.192.228.250") do
        insist { subject.get("foo")[0] } == "199.192.228.250"
        insist { subject.get("foo")[1] } == "carrera.databits.net"
      end
    end

    describe "dns reverse lookup, not an IP" do
      config <<-CONFIG
        filter {
          dns {
            reverse => "foo"
          }
        }
      CONFIG

      sample("foo" => "not.an.ip") do
        insist { subject.get("foo") } == "not.an.ip"
      end
    end

    describe "dns resolve lookup, replace" do
      config <<-CONFIG
        filter {
          dns {
            resolve => ["host"]
            action => "replace"
            add_tag => ["success"]
          }
        }
      CONFIG

      sample("host" => "carrera.databits.net") do
        insist { subject.get("host") } == "199.192.228.250"
        insist { subject.get("tags") } == ["success"]
      end
    end

    describe "dns resolve lookup, missing field" do
      let(:plugin) { ::LogStash::Filters::DNS.new("resolve" => "foo") }
      let(:event) { ::LogStash::Event.new }

      before do
        plugin.register
        allow(plugin.logger).to receive(:warn).with(any_args)
      end

      it "should not throw an error when filtering" do
        expect do
          plugin.filter(event)
        end.not_to raise_error
      end

      it "should log a warning" do
        plugin.filter(event)
        expect(plugin.logger).to have_received(:warn).with("DNS filter could not resolve missing field", :field => "foo")
      end
    end

    describe "dns fail resolve lookup, don't add tag" do
      config <<-CONFIG
        filter {
          dns {
            resolve => ["host1", "host2"]
            action => "replace"
            add_tag => ["success"]
          }
        }
      CONFIG

      sample("host1" => "carrera.databits.net", "host2" => "nonexistanthostname###.net") do
        insist { subject.get("tags") }.nil?
        insist { subject.get("host1") } == "199.192.228.250"
        insist { subject.get("host2") } == "nonexistanthostname###.net"
      end
    end

    describe "dns resolves lookups, adds tag" do
      config <<-CONFIG
        filter {
          dns {
            resolve => ["host1", "host2"]
            action => "replace"
            add_tag => ["success"]
          }
        }
      CONFIG

      sample("host1" => "carrera.databits.net", "host2" => "carrera.databits.net") do
        insist { subject.get("tags") } == ["success"]
      end
    end

    describe "dns resolves and reverses, fails last, no tag" do
      config <<-CONFIG
        filter {
          dns {
            resolve => ["host1"]
            reverse => ["ip1", "ip2"]
            action => "replace"
            add_tag => ["success"]
          }
        }
      CONFIG

      sample("host1" => "carrera.databits.net",
             "ip1" => "127.0.0.1",
             "ip2" => "128.0.0.1") do
        insist { subject.get("tags") }.nil?
        insist { subject.get("host1") } == "199.192.228.250"
        insist { subject.get("ip1") } == "localhost"
        insist { subject.get("ip2") } == "128.0.0.1"
      end
    end

    describe "dns resolve lookup, replace (on a field)" do
      config <<-CONFIG
        filter {
          dns {
            resolve => "foo"
            action => "replace"
          }
        }
      CONFIG

      sample("foo" => "carrera.databits.net") do
        insist { subject.get("foo") } == "199.192.228.250"
      end
    end

    describe "dns resolve lookup, skip multi-value" do
      config <<-CONFIG
        filter {
          dns {
            resolve => "foo"
            action => "replace"
          }
        }
      CONFIG

      sample("foo" => ["carrera.databits.net", "foo.databits.net"]) do
        insist { subject.get("foo") } == ["carrera.databits.net", "foo.databits.net"]
      end
    end

    describe "dns resolve lookup, append" do
      config <<-CONFIG
        filter {
          dns {
            resolve => "foo"
            action => "append"
          }
        }
      CONFIG

      sample("foo" => "carrera.databits.net") do
        insist { subject.get("foo")[0] } == "carrera.databits.net"
        insist { subject.get("foo")[1] } == "199.192.228.250"
      end
    end

    describe "dns resolve lookup, append with multi-value does nothing" do
      config <<-CONFIG
        filter {
          dns {
            resolve => "foo"
            action => "append"
          }
        }
      CONFIG

      sample("foo" => ["carrera.databits.net", "foo.databits.net"]) do
        insist { subject.get("foo") } == ["carrera.databits.net", "foo.databits.net"]
      end
    end

    describe "dns resolve lookup, not a valid hostname" do
      config <<-CONFIG
        filter {
          dns {
            resolve=> "foo"
          }
        }
      CONFIG

      sample("foo" => "does.not.exist") do
        insist { subject.get("foo") } == "does.not.exist"
      end
    end

    describe "dns resolve lookup, single custom nameserver" do
      config <<-CONFIG
        filter {
          dns {
            resolve => ["host"]
            action => "replace"
            nameserver => "8.8.8.8"
          }
        }
      CONFIG

      sample("host" => "carrera.databits.net") do
        insist { subject.get("host") } == "199.192.228.250"
      end
    end

    describe "dns resolve lookup, multiple nameserver fallback" do
      config <<-CONFIG
        filter {
          dns {
            resolve => ["host"]
            action => "replace"
            nameserver => ["127.0.0.99", "8.8.8.8"]
          }
        }
      CONFIG

      sample("host" => "carrera.databits.net") do
        insist { subject.get("host") } == "199.192.228.250"
      end
    end

    describe "dns resolve lookup, multiple nameserver fallback" do
      config <<-CONFIG
        filter {
          dns {
            resolve => ["host"]
            action => "replace"
            nameserver => ["127.0.0.99", "8.8.8.8"]
          }
        }
      CONFIG

      sample("host" => "carrera.databits.net") do
        insist { subject.get("host") } == "199.192.228.250"
      end
    end

    describe "failed cache" do

      let(:subject) { LogStash::Filters::DNS.new(config) }
      let(:event1) { LogStash::Event.new("message" => "unkownhost") }
      let(:event2) { LogStash::Event.new("message" => "unkownhost") }

      before(:each) do
        allow(subject).to receive(:getaddress).and_raise Resolv::ResolvError
        subject.register
      end

      context "when enabled" do
        let(:config) { { "resolve" => ["message"], "failed_cache_size" => 3 } }

        it "should cache a failed lookup" do
          expect(subject).to receive(:getaddress).once
          subject.filter(event1)
          subject.filter(event2)
        end
      end

      context "when disabled" do
        let(:config) { { "resolve" => ["message"] } }

        it "should not cache a failed lookup" do
          expect(subject).to receive(:getaddress).twice
          subject.filter(event1)
          subject.filter(event2)
        end
      end
    end

    describe "hit cache" do

      let(:subject) { LogStash::Filters::DNS.new(config) }
      let(:event1) { LogStash::Event.new("message" => "unkownhost") }
      let(:event2) { LogStash::Event.new("message" => "unkownhost") }

      before(:each) do
        allow(subject).to receive(:getaddress).and_return("127.0.0.1")
        subject.register
      end

      context "when enabled" do
        let(:config) { { "resolve" => ["message"], "hit_cache_size" => 3 } }

        it "should cache a succesful lookup" do
          expect(subject).to receive(:getaddress).once
          subject.filter(event1)
          subject.filter(event2)
        end
      end

      context "when disabled" do
        let(:config) { { "resolve" => ["message"] } }

        it "should not cache a successful lookup" do
          expect(subject).to receive(:getaddress).twice
          subject.filter(event1)
          subject.filter(event2)
        end
      end
    end

    describe "retries" do

      let(:host) { "unknownhost" }
      let(:subject) { LogStash::Filters::DNS.new(config) }
      let(:event) { LogStash::Event.new("message" => host) }
      let(:max_retries) { 3 }
      let(:config) { { "resolve" => ["message"], "max_retries" => max_retries, "failed_cache_size" => 10 } }

      before(:each) { subject.register }

      context "when failing permanently" do
        before(:each) do
          allow(subject).to receive(:getaddress).and_raise(Timeout::Error)
        end

        it "should fail a resolve after max_retries" do
          expect(subject).to receive(:getaddress).exactly(max_retries+1).times
          subject.filter(event)
        end

        it "should cache the timeout" do
          expect do
            subject.filter(event)
          end.to change { subject.failed_cache[host] }.from(nil).to(true)
        end
      end

      context 'with a label too long' do
        let(:host) { "#{'0' * 64}.com" }

        it 'should not raise' do
          subject.filter(event)
        end
      end

      context "when failing temporarily" do
        before(:each) do
          allow(subject).to receive(:getaddress) do
            @try ||= 0
            if @try < 2
              @try = @try + 1
              raise Timeout::Error
            else
              "127.0.0.1"
            end
          end
        end

        it "should resolve before max_retries" do
          expect(subject).to receive(:getaddress).exactly(3).times
          subject.filter(event)
        end
      end
    end
  end

  describe "with search configuration" do
    subject(:dns_filter_plugin) { LogStash::Filters::DNS.new(config) }

    before(:each) do
      subject.register
    end

    context "search domain specified" do
      let(:config) { { "resolve" => ["domain"], "action" => "replace", "nameserver" => { "address" => ["1.2.3.4"], "search" => "elastic.co" } } }
      let(:event) { LogStash::Event.new("domain" => "training") }

      it "will expand training to training.elastic.co" do
        allow(Resolv::DNS::Name).to receive(:new).and_call_original

        # This is implementation specific but the only way I found to verify that the "search" option was working.
        expect(Resolv::DNS::Name).to receive(:new).with([Resolv::DNS::Label::Str.new("training"), Resolv::DNS::Label::Str.new("elastic"), Resolv::DNS::Label::Str.new("co")]).and_call_original

        subject.filter(event)
      end
    end
  end

  describe "with nameserver configuration" do
    subject(:dns_filter_plugin) { LogStash::Filters::DNS.new(config) }

    before(:each) do
      allow(Resolv::DNS).to receive(:new).and_call_original
    end

    context 'nameserver specified as a string' do
      let(:config) { { "nameserver" => "8.8.8.8" } }

      it 'sets up the expected Resolv::DNS' do
        dns_filter_plugin.register

        expect(Resolv::DNS).to have_received(:new).with(:nameserver => ["8.8.8.8"], :search => [], :ndots => 1)
      end
    end

    context 'nameserver specified as an array of strings' do
      let(:config) { { "nameserver" => ["8.8.8.8", "8.8.4.4"] } }

      it 'sets up the expected Resolv::DNS' do
        dns_filter_plugin.register

        expect(Resolv::DNS).to have_received(:new).with(:nameserver => ["8.8.8.8", "8.8.4.4"], :search => [], :ndots => 1)
      end
    end

    context 'nameserver specified as a hash' do
      context 'with only string address' do
        let(:config) { { "nameserver" => { "address" => "8.8.8.8" } } }

        it 'sets up the expected Resolv::DNS' do
          dns_filter_plugin.register

          expect(Resolv::DNS).to have_received(:new).with(:nameserver => ["8.8.8.8"], :search => [], :ndots => 1)
        end
      end
      context 'with only array address' do
        let(:config) { { "nameserver" => { "address" => ["8.8.8.8", "8.8.4.4"] } } }

        it 'sets up the expected Resolv::DNS' do
          dns_filter_plugin.register

          expect(Resolv::DNS).to have_received(:new).with(:nameserver => ["8.8.8.8", "8.8.4.4"], :search => [], :ndots => 1)
        end
      end
      context 'with search domains' do
        let(:config) do
          {
            "nameserver" => {
              "address" => ["127.0.0.1"],
              "search" => search_domains
            }
          }
        end

        {
          "string" => "internal.net",
          "array of strings" => ["internal.net", "internal1.com"]
        }.each do |desc, search_domains_arg|
          let(:search_domains) { search_domains_arg }
          context "as #{desc}" do
            it 'sets up the expected Resolv::DNS' do
              dns_filter_plugin.register

              expect(Resolv::DNS).to have_received(:new).with(:nameserver => ["127.0.0.1"], :search => Array(search_domains), :ndots => 1)
            end
          end
        end
      end
    end
  end

  describe "without nameserver configuration" do
    subject(:dns_filter_plugin) { LogStash::Filters::DNS.new(config) }

    context 'nameserver not specified' do
      let(:config) { { "resolve" => ["domain"], "action" => "replace" } }

      it 'sets up the expected Resolv::DNS without arguments' do
        # We expect that when no nameserver option is specified
        # Resolv::DNS.new will be called without arguments thus reading /etc/resolv.conf
        # for its configuration which is the desired behaviour for backward compatibility

        expect(Resolv::DNS).to receive(:new).once.with(no_args)
        dns_filter_plugin.register
      end
    end
  end

  describe "with hostsfile integration" do
    describe "lookup using fixture hosts file" do
      let(:subject) { LogStash::Filters::DNS.new(config) }
      let(:hostsfile) { File.join(File.dirname(__FILE__), "..", "fixtures", "hosts") }
      # From the custom hosts file
      # 10.10.0.1 xn--d1acpjx3f.xn--p1ai  # -> Яндекс.рф
      # 10.10.0.2 xn--mller-kva.com       # -> müller.com

      before(:each) do
        subject.register
        subject.filter(event)
      end

      context "when domain is an IDN" do
        let(:config) { { "resolve" => ["domain"], "action" => "replace", "hostsfile" => [hostsfile]} }
        let(:event) { LogStash::Event.new("domain" => "Яндекс.рф") }

        it "should return the IP" do
          expect(event.get("domain")).to eq("10.10.0.1")
        end
      end

      context "when IP points to an IDN" do
        let(:config) { { "reverse" => ["domain"], "action" => "replace", "hostsfile" => [hostsfile]} }
        let(:event) { LogStash::Event.new("domain" => "10.10.0.2") }

        it "should return the IDN" do
          expect(event.get("domain")).to eq("müller.com")
        end
      end
    end
  end
end
