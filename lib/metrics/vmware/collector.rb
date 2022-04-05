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
                    :root,
                    :refs,
                    :counters

        def initialize
            @log       = Logger.new(STDOUT)
            @options   = get_command_options()
            @connect   = make_connection()
            @si        = @connect.serviceInstance
            @content   = @si.content
            @perfman   = @content.perfManager
            @viewman   = @content.viewManager
            @root      = @content.rootFolder
            @inv       = get_inventory()
            @refs      = make_refs()
            @counters  = get_counters_by_key()
            status()
        end
        
        def status
            log.info("Object Counts")
            log.info("Virtual Machines: #{vms.length}")
            log.info("Hosts: #{hosts.length}")
            log.info("Clusters: #{clusters.length}")
            log.info("Datastores: #{datastores.length}")
        end

        def get_counters_by_key
            ret = {}
            perfman.perfCounter.map do |c|
                props = c.props
                nameinfo = props[:nameInfo].props
                groupinfo = props[:groupInfo].props
                unitinfo = props[:unitInfo].props
                type = groupinfo[:key]
                name = nameinfo[:key]
                rollup = props[:rollupType]
                full = "#{type}.#{name}.#{rollup}"
                key = props[:key]
                ret[key] = full
            end
            return ret
        end

        def collect
            log.info("Starting VMware Collector")
            require 'debug'
            puts :DEBUGGING
        end

        def hosts
            idx = get_ref_idx_by_class(:HostSystem)
            return inv.values_at(*idx)
        end

        def vms
            idx = get_ref_idx_by_class(:VirtualMachine)
            return inv.values_at(*idx)
        end

        def datastores
            idx = get_ref_idx_by_class(:Datastore)
            return inv.values_at(*idx)
        end

        def clusters
            idx = get_ref_idx_by_class(:ClusterComputeResource)
            return inv.values_at(*idx)
        end

        def close
            connect.close
        end

        private

        def make_refs
            log.info("Makeing Reference Maps")
            ret = {}
            inv.each do |mo| 
                name = mo.name
                moid = mo.to_s.split('"')[1]
                type = moid.split('-',2).first
                ret[moid] = {
                    name: name,
                    class: mo.class.to_s.to_sym
                }
            end
            log.info("Done")
            return ret
        end

        def get_ref_idx_by_class(type=:VirtualMachine)
            refs.values.each_with_index.map do |x,i| 
                i if x[:class] == type
            end.compact
        end
        
        def available_metrics(mo)
            @perfman.QueryAvailablePerfMetric( { entity: mo } )
        end

        def get_command_options
            opts = Optimist::options do
                opt :server, "vCenter IP or FQN", :type => :string, :required => true
                opt :user, "vCenter User", :type => :string
                opt :password, "Password", :type => :string
                opt :port, "Port", :type => :integer, :default => 443
                opt :object, "Object to Collect", :type => :string, :default => 'vm'
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

        def get_inventory
            ret = []
            ret += get_objects(root,[], true)
            return ret
        end

        def get_objects(obj,type,recursive)
            viewman.CreateContainerView( {
                 type: type,
                 container: obj,
                 recursive: recursive 
            } ).view.map{ |o| o }
        end


        def make_query_spec(entity)
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