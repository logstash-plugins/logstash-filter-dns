# encoding: utf-8
require "resolv"

class Resolv
  class DNS

    def timeouts=(timeouts)
      @config.timeouts = timeouts
    end

    class Config

      def timeouts=(values)
        if values
          values = Array(values)
          values.each do |t|
            Numeric === t or raise ArgumentError, "#{t.inspect} is not numeric"
            t > 0.0 or raise ArgumentError, "timeout=#{t} must be postive"
          end
          @timeouts = values
        else
          @timeouts = nil
        end
      end

      def generate_timeouts
        return @timeouts if !@timeouts.nil?
        ts = [InitialTimeout]
        ts << ts[-1] * 2 / @nameserver_port.length
        ts << ts[-1] * 2
        ts << ts[-1] * 2
        return ts
      end
    end
  end
end
