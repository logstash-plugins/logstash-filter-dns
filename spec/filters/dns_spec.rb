# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/dns"
require "resolv"

describe LogStash::Filters::DNS do
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
      insist { subject["foo"] } == "carrera.databits.net"
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
      insist { subject["foo"][0] } == "199.192.228.250"
      insist { subject["foo"][1] } == "carrera.databits.net"
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
      insist { subject["foo"] } == "not.an.ip"
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
      insist { subject["host"] } == "199.192.228.250"
      insist { subject["tags"] } == ["success"]
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
      insist { subject["tags"] }.nil?
      insist { subject["host1"] } == "199.192.228.250"
      insist { subject["host2"] } == "nonexistanthostname###.net"
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
      insist { subject["tags"] } == ["success"]
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
      insist { subject["tags"] }.nil?
      insist { subject["host1"] } == "199.192.228.250"
      insist { subject["ip1"] } == "localhost"
      insist { subject["ip2"] } == "128.0.0.1"
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
      insist { subject["foo"] } == "199.192.228.250"
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
      insist { subject["foo"] } == ["carrera.databits.net", "foo.databits.net"]
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
      insist { subject["foo"][0] } == "carrera.databits.net"
      insist { subject["foo"][1] } == "199.192.228.250"
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
      insist { subject["foo"] } == ["carrera.databits.net", "foo.databits.net"]
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
      insist { subject["foo"] } == "does.not.exist"
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
      insist { subject["host"] } == "199.192.228.250"
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
      insist { subject["host"] } == "199.192.228.250"
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
      insist { subject["host"] } == "199.192.228.250"
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

    let(:subject) { LogStash::Filters::DNS.new(config) }
    let(:event) { LogStash::Event.new("message" => "unkownhost") }
    let(:max_retries) { 3 }
    let(:config) { { "resolve" => ["message"], "max_retries" => max_retries } }

    before(:each) { subject.register }

    context "when failing permanently" do
      before(:each) do
        allow(subject).to receive(:getaddress).and_raise(Timeout::Error)
      end

      it "should fail a resolve after max_retries" do
        expect(subject).to receive(:getaddress).exactly(max_retries+1).times
        subject.filter(event)
      end
    end

    context "when failing temporarily" do
      before(:each) do
        allow(subject).to receive(:getaddress) do
          @try ||= 0
          if @try < 3
            @try = @try + 1
            raise Timeout::Error
          else
            return "127.0.0.1"
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
