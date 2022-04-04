require 'metrics/vmware/version'

module Metrics;

    class VmwareCollector

        def initialize
            puts "init"
            puts Vmware::VERSION
        end
    end

end