require 'rbvmomi.rb'
require 'csv'
require 'yaml'
require 'optparse'
require 'logger'
require 'fileutils'
require 'awesome_print'
require 'byebug'
require 'json'

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
                    :counters,
                    :perfids

        def initialize
            setup()
            status()
            run()
            close()
        end


        def get_command_options
            opts = Optimist::options do
                opt :server, "vCenter IP or FQN", :type => :string, :required => true
                opt :user, "vCenter User", :type => :string
                opt :password, "Password", :type => :string
                opt :port, "Port", :type => :integer, :default => 443
                opt :id, "Metrics to Get (Regexp `name`)", :type => :string, :default => '^(cpu|mem)\.usage\.average'
                opt :get, "Get the Perf data", :type => :flag
                opt :show, "Show the Perf IDs", :type => :flag
                opt :file, "Output json file", :type => :string, :default => File.join(ENV['HOME'],"vmware-#{Time.now.to_i}.json")
            end
            return opts
        end

        def run
            log.info("Starting VMware Collector")
            case
            when options[:show_given]
                log.info("Show performance counter IDs by (regexp) name.")
                list = get_counters()
                list.each{ |x,y| printf("%10s   %s\n",x,y) }
            when options[:get_given]
                log.info("Show performance data by (regexp) name.")
                pi = get_counters().keys
                qry = make_query_spec([hosts, vms],pi)
                results = run_query(qry)
                write_results(results)
            else
                log.info("Need something to do. Try `--get` or `--show`")
            end
            return self
        end

        def run_query(qry)
            ret = []
            raise "qry param must be an array" unless qry.is_a?(Array)
            results = perfman.QueryPerf( { querySpec: qry } ) # RbVmomi::VIM::PerfEntityMetric
            results.each do |result|
                ret2 = {}
                ret2.store(:entity, result.entity.name)
                ret2.store(:timestamps, result.sampleInfo.map{ |x| x.props[:timestamp] })
                result.value.each do |vals|
                    counter = vals[:id].props[:counterId]
                    metric = perfids[counter]
                    ret2.store(metric, {
                        inst: vals[:id].props[:instance],
                        values: vals.value
                    })
                end
                ret << ret2
            end
            return ret
        end

        def close
            connect.close
        end

        private

        def write_results(results)
            f = File.new(options.file,'w')
            f.write(results.to_json)
            f.close
        end
        def setup
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
            @perfids, @counters = get_counters_by_key()
        end

        def get_counters
            regexp = options[:id].nil? ? // : Regexp.new(options[:id])
            list = get_perf_ids_by_regex(regexp)
            return list
        end

        def status
            log.info("Object Counts")
            log.info("Virtual Machines: #{vms.length}")
            log.info("Hosts: #{hosts.length}")
            log.info("Clusters: #{clusters.length}")
            log.info("Datastores: #{datastores.length}")
        end

        def get_counters_by_key
            ret1, ret2 = {}, {}
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
                ret1[key] = full
                ret2[key] = c
            end
            return [ ret1, ret2 ]
        end

        def get_perf_ids_by_regex(regex=//)
            ret = perfids.select{ |x,y| y =~ regex }
            return ret
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

        def get_performace_data(specs)
            perf.QueryPerf( { querySpec: specs })
        end

        def make_query_spec(entities,counter_ids,instance="")
            ret = []
            entities.flatten.each do |ent|
                interval = perfman.QueryPerfProviderSummary( { entity: ent } ).refreshRate
                perf_metric_ids = counter_ids.map{ |x| RbVmomi::VIM::PerfMetricId( {counterId: x, instance: instance } ) }
                ret << RbVmomi::VIM::PerfQuerySpec(
                    :entity     => ent,
                    :metricId   => perf_metric_ids,
                    :intervalId => interval
                    # :startTime  => starttime,
                    # :endTime    => endtime,
                )
            end 
            return ret
        end

    end

end