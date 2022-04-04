require 'rbvmomi.rb'
require 'csv'
require 'yaml'
require 'optparse'
require 'logger'
require 'fileutils'
require 'awesome_print'

require 'metrics/vmware/version'
module Metrics;

    class VmwareCollector

        attr_reader :log, 
                    :connect, 
                    :options,
                    :inv,
                    :si,
                    :content,
                    :perfman,
                    :viewman,
                    :uuid,
                    :root

        def initialize
            @options   = get_vcenter_options()
            @log       = Logger.new(STDOUT)
            @connect   = make_connection()
            @si        = @connect.serviceInstance
            @content   = @si.content
            @perfman   = @content.perfManager
            @viewman   = @content.viewManager
            @uuid      = @content.about.props[:instanceUuid].downcase
            @root      = @content.rootFolder
            @inv       = get_inventory()
        end

        def close
            connect.close
        end

        def available_metrics(mo)
            @perfman.QueryAvailablePerfMetric( { entity: mo } )
        end

        def get_vcenter_options
            opts = Optimist::options do
                opt :server, "vCenter IP or FQN", :type => :string, :required => true
                opt :user, "vCenter User", :type => :string
                opt :password, "Password", :type => :string
                opt :outdir, "Output Directory", :type => :string, :default => File.join(ENV['HOME'],'vm-metrics')
                opt :port, "Port", :type => :integer, :default => 443
                opt :objects, "Objects to Collect", :type => :strings, :default => %w[vmguest]
                opt :debug, "Debug", :type => :string, :default => File.join(ENV['HOME'],'vm-metrics')
            end
            return opts
        end              

        def make_connection
            connection = RbVmomi::VIM.connect(
                host: options.server,
                user: options.user,
                password: options.password,
                insecure: true, debug: options.vcdebug
            )
        end

        def collect
            log.info("Starting VMware Collector")
            require 'debug'
            puts :DEBUGGING
        end

        def get_inventory
            ret = Set.new
            ret += get_objects(root,[], true)
            return ret.to_a
        end

        def get_objects(obj,type,recursive)
            viewman.CreateContainerView( {
                 type: type,
                 container: obj,
                 recursive: recursive 
            } ).view.map{ |o| o }
        end


        def make_query_spec()
            ret << RbVmomi::VIM::PerfQuerySpec(
                :entity     => entity,
                # :intervalId => @sample_seconds.to_s,
                # :startTime  => starttime,
                # :endTime    => endtime,
                :metricId   => [
                    RbVmomi::VIM::PerfMetricId
                ]
            )
            return ret
        end

    end

end