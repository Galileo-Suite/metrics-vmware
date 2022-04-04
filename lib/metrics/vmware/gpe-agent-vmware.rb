#!/usr/bin/env ruby

# Use rbvmomi gem to access vCenter and vmware.
require 'bundler/setup'
require 'rubygems'
require 'rbvmomi.rb'
require 'awesome_print'
require 'csv'
require 'yaml'
require 'optparse'
require 'logger'
require 'fileutils'


# Inventory class for consolidated access to inventory data
class Inventory

  attr_accessor :name, :type, :class, :readable, :id, :uuid, :entity, :moid, :details

  def initialize(entity,log)
    @type        = entity.class.to_s.to_sym
    @class       = entity.class.to_s
    @readable    = "#{entity.to_s.match(/\"(.*)\"/)[1]}"
    @moid        = readable
    @id          = "#{@type}-#{@readable}"
    # Put this here to filter on guest type but didn't enable it yet. RDavis 4/2021
    # @details     = Details.new(entity)
    @entity      = entity
    begin
      @name = entity.name
    rescue Exception => e
      @name = "name-fetch-failed-#{@id}"
      log.warn "Error getting inventory 'name' for: #{@id} (#{e.message}).  name set to: #{@name}"
    end
    begin
      @uuid = get_uuid(entity)
    rescue Exception => e
      @uuid = "uuid-fetch-failed-#{@id}"
      log.warn "Error getting inventory 'uuid' for: #{@id} (#{e.message}).  uuid set to: #{@uuid}"
    end
  end

  def get_uuid(entity)
    type = entity.class.to_s.to_sym
    if type == :Datastore
      case entity.summary.type
        when "VMFS"
          return entity.info.vmfs.uuid
        when "NFS"
          return "#{type}-#{entity.to_s.match(/\"(.*)\"/)[1]}"
        else return "#{type}-#{entity.to_s.match(/\"(.*)\"/)[1]}"
      end
    end
    return entity.hardware.systemInfo.uuid if type == :HostSystem
    return entity.config.instanceUuid      if type == :VirtualMachine
    return "#{type}-#{entity.to_s.match(/\"(.*)\"/)[1]}"
  end

end

class Details
  attr_reader :get
  def initialize(entity)
    @get = OpenStruct.new
    case entity.class.to_s.to_sym
    when :VirtualMachine
      get.guest = entity.guest
    else
      get.guest = false
    end
  end
end

# For log files
class MultiDelegator

  def initialize(*targets)
    @targets = targets
  end

  def self.delegate(*methods)
    methods.each do |m|
      define_method(m) do |*args|
        @targets.map { |t| t.send(m, *args) }
      end
    end
    self
  end

  class <<self
    alias to new
  end

end

# Collect the options
class Options

  attr_reader   :seconds
  attr_accessor :debug,
                :vcdebug,
                :vcprofile,
                :server,
                :user,
                :password,
                :output_dir,
                :cache_dir,
                :test_run,
                :num_threads,
                :config,
                :no_trend,
                :vsan,
                :no_config,
                :rerun_tries

  def usage(opts)
    puts opts
    exit(1)
  end

  def initialize(args)
    @debug        = false
    @vcdebug      = false
    @vcprofile    = false
    @no_trend     = false
    @vsan         = false
    @no_config    = false
    @test_run     = false
    @seconds      = 1200
    @num_threads  = 4
    @config       = "#{File.expand_path(File.dirname(__FILE__))}/../../../etc/gpe-agent-vmware.yml"
    @output_dir   = "/tmp"
    @rerun_tries  = 2

    options = OptionParser.new do |opts|
      opts.banner = "Usage: #{$0} [options]"
      opts.separator ""
      opts.on("-S", "--server SERVER", "IP/Hostname of vCenter Server") { |server| @server = server }
      opts.on("-u", "--user USER", "vCenter Username") { |user| @user = user }
      opts.on("-p", "--password PW", "vCenter Password") { |password| @password = password }
      opts.on("-o", "--directory DIR", "Output directory") { |dir| @output_dir = dir }
      opts.on("-a", "--cache_directory DIR", "Cache directory")  { |dir| @cache_dir  = dir }
      opts.on("-r", "--rerun-tries NUM", "Rerun retries") { |number| @rerun_tries = number.to_i }
      opts.on("-c", "--credentials SYSTEM", "Use cred file for SYSTEM") { |sys|
        ENV['GPE_HOME'] || (puts("GPE_HOME is not set."); exit 1)
        cmd       = "#{ENV['GPE_HOME']}/bin/gpe-agent-vmware-credentials get -c #{ENV['GPE_HOME']}/etc/gpe-agent-vmware.d/#{sys}.cred -k #{ENV['GPE_HOME']}/etc/vmware.key"
        creddata  = `#{cmd}`.lines.map(&:chomp)
        @user     = creddata.first
        @password = creddata.last
      }
      opts.on("-d", "--debug", "Debug mode") {@debug = true}
      opts.on("-s", "--seconds SECONDS", "Seconds Window (Default: 1200)") { |seconds| @seconds = seconds.to_i }
      opts.on("-v", "--vcdebug", "vCenter Debug mode") {@vcdebug = true}
      opts.on("-P", "--vcprofile", "vCenter Perf Profile") {@vcprofile = true}
      opts.on(      "--no-trend", "Skip trend collection") {@no_trend = true}
      opts.on(      "--vsan", "Collect VSAN data") {@vsan = true}
      opts.on(      "--no-config", "Skip config collection") {@no_config = true}
      opts.on(      "--small-config", "Collect minimal configuration") { @config = "#{File.expand_path(File.dirname(__FILE__))}/../../../etc/gpe-agent-vmware.yml.EXAMPLE-SMALL" }
      opts.on("-t", "--test", "Test connectivity only") {@test_run = true}
      opts.on_tail("-h", "--help", "Show this message") {puts opts; exit}
      opts.on("-t", "--threads THREADS", "Number of threads") {|threads| @num_threads = threads.to_i}
      opts.on("", "--config FILE", "Configure file.") { |config| @config = config }

    end
    options.parse!
    usage(options) if @server.nil? || @user.nil? || @password.nil?
  end

end

# VMWare collector
class VMWareCollector

  class VcenterConfigurationError < Exception; end

  attr_accessor :last_try

  # Create the VMWareCollector based on options passed in ARGV (options).
  def initialize(options,log)
    @profiles   = {}
    @rerun      = false
    @is_rerun   = false
    @last_try   = false
    @rerun_list = Array.new
    @stats      = Array.new
    @debug      = options.debug
    @vcprofile  = options.vcprofile
    @options    = options
    @exit_code  = 0
    @no_trend   = options.no_trend
    @vsanrun    = options.vsan
    @no_config  = options.no_config
    @connect    = RbVmomi::VIM.connect host: options.server, user: options.user, password: options.password, insecure: true, debug: options.vcdebug
    @connect.profiling = true
    @profiles[:main] = @connect.profile_summary if @vcprofile
    @user       = options.user
    connection_setup
    @config     = YAML::load(File.open( options.config ))
    @quickinfo  = Hash.new(false)
    @setup      = @config[:setup]
    @collect    = @config[:collect]
    @props      = @config[:props]
    @vsantypes  = @config[:vsan_types]
    @vsan       = get_vsan(@connect)
    @vsandata   = nil
    @log        = log
    @threadded_connections_stats  = Array.new
    @threadded_connections_config = Array.new
  end

  def make_excludes(config)
    return [] if config.is_a?(Array)
    ret = []
    return nil if config.nil? or config['excludes'].nil?
    ret = Regexp.new(config['excludes'].join('|'), Regexp::IGNORECASE)
    return ret
  end

  def get_vsan_space(vsan,clusters)
    start = Time.now.to_f
    @log.info "Get VSAN Space Statistics"
    space = clusters.map{ |cluster| vsan.vsanSpaceReportSystem.VsanQuerySpaceUsage(cluster: cluster.entity) }
    @log.info "End Get VSAN Space Statistics #{(Time.now.to_f - start).round(4)} Seconds"
    return space
  end

  def get_vsan_health(vsan,clusters)
    start = Time.now.to_f
    @log.info "Get VSAN Health Statistics"
    health = clusters.map{ |cluster| vsan.vsanPerformanceManager.VsanPerfQueryClusterHealth(cluster: cluster.entity) }
    @log.info "End Get VSAN Health Statistics #{(Time.now.to_f - start).round(4)} Seconds"
    return health
  end

  def get_vsan_node(vsan,clusters)
    start = Time.now.to_f
    @log.info "Get VSAN Node Information"
    node = clusters.map{ |cluster| vsan.vsanPerformanceManager.VsanPerfQueryNodeInformation(cluster: cluster.entity) }
    @log.info "End Get VSAN Node Information #{(Time.now.to_f - start).round(4)} Seconds"
    return node
  end

  def get_vsan_perf(vsan,clusters,stime,etime)
    ret = {}
    start = Time.now.to_f
    @log.info "Start VSAN performance statistics collection."
    @vsantypes.each do |type|
      spec = RbVmomi::VIM::VsanPerfQuerySpec( entityRefId: "#{type}:*", endTime: etime, startTime: stime)
      @log.info "Get VSAN Performance Statistics type: #{type}"
      clusters.each do |cluster|
        ret[cluster.id] ||= {}
        begin
          ret[cluster.id][type] = vsan.vsanPerformanceManager.VsanPerfQueryPerf(querySpecs: [ spec ], cluster: cluster.entity)
        rescue Exception => e
          @log.warn "Unable to capture VSAN performance statistics: #{type}, cluster: #{cluster.name}: #{e.message}"
          e.backtrace.each{ |o| @log.debug o }
        end
      end
    end
    @log.info "End Get VSAN Performance Statistics #{(Time.now.to_f - start).round(4)} Seconds"
    return ret
  end

  def get_vsan(conn)
    api_info = conn.serviceContent.about
    api_type = api_info.apiType
    api_ver  = api_info.apiVersion.split(".").first.to_i
    if api_type == "VirtualCenter" and api_ver >= 6
      require_relative 'vsanmgmt.api'
      require_relative 'vsanapiutils'
      vsanobj = conn.vsan
    else
      @log.warn "VSAN methods require vCenter v6 or greater. #{api_type} #{api_info.apiVersion} is unsupported."
      return nil
    end
    return vsanobj
  end

  def all_clusters
    @inventory.select{ |o| o.class == 'ClusterComputeResource' }
  end

  def connection_setup
    @si         = @connect.serviceInstance
    @content    = @si.content
    @perfman    = @content.perfManager
    @viewman    = @content.viewManager
    @uuid       = @content.about.props[:instanceUuid].downcase
    @root       = @content.rootFolder
  end

  def reconnect
    @rerun = false
    @is_rerun = true
    @log.info("Reconnecting: Metrics to retry: #{@rerun_list.length}")
    @connect = RbVmomi::VIM.connect(
      host: @options.server,
      user: @options.user,
      password: @options.password,
      insecure: true, debug: @options.vcdebug
    )
    @connect.profiling = true
    @profiles[:main_reconnect] = @connect.profile_summary if @vcprofile

    @threadded_connections_stats  = Array.new
    @threadded_connections_config = Array.new
    connection_setup
  end

  def exit_code
    return @exit_code
  end

  def collect

    # Run all setup but only the first time through
    collection_setup unless @is_rerun

    # Capture and save trend data
    unless @no_trend
      time = Time.now.to_i
      @log.info "Capture Trend Data"
      if @is_rerun
        @query_specs = @rerun_list
        @rerun_list = Array.new
        @log.warn("Retry for failed metrics: #{@query_specs.length}")
        @log.warn("Rerun List Length: #{@rerun_list.length}")
      end
      @stats += collect_statistics(@query_specs)
      @log.info "End Capture Trend Data  #{Time.now.to_i-time} Seconds"
      if @rerun == true and @last_try == false
        @log.warn "Starting rerun for failed collection."
        return
      elsif @rerun == true and @last_try == true
        @log.warn "Retry attempts exceeded, continuing to config data.  #{@rerun_list.length} object(s) not collected."
      else
        @log.info "Trend Collection Complete."
      end
    end

    if @no_config
      @log.warn "Configuration data will be retreived from cache: '#{@options.cache_dir}'"
      copy_config_from_cache
    else
      # get_config returns a Hash keyed by Mananaged Entity obj
      time = Time.now.to_i
      @log.info "Capture Config Data"
      config = get_config(@inventory,@props)
      @log.info "End Capture Config Data  #{Time.now.to_i-time} Seconds"
      # Capture the hierarchy and config details
      # Thread.new{
        time = Time.now.to_i
        @log.info "Capture Inventory Tree #{@inventory.length} object(s)"
        inventory_tree(@inventory,config,@vcenter_name,@vcenter_uuid)
        @log.info "End Capture Inventory Tree  #{Time.now.to_i-time} Seconds"
      # }
      time = Time.now.to_i
      @log.info "Collect All Config"
      collect_all_config(config)
      copy_config_to_cache
      @log.info "End Collect All Config  #{Time.now.to_i-time} Seconds"
    end

    # Save all the trend data to disk for send
    unless @no_trend
      time = Time.now.to_i
      @log.info "Save Trend Data"
      save_trend_data(@stats)
      @log.info "End Save Trend Data  #{Time.now.to_i-time} Seconds"
    end

    # Get a record of failed metrics if any
    if @query_specs.length > 0
      write_string_to_file("#{@options.output_dir}/InfoFailedPerfQueries.txt", @query_specs.to_yaml);
    end

    ap @profiles if @vcprofile

  end

  def copy_config_from_cache
    src = "#{@options.cache_dir}/Config*.txt"
    dst = "#{@options.output_dir}"
    files = Dir.glob(src)
    @log.info "Copying files from cache directory: '#{src}'"
    FileUtils.cp(files,dst)
  end

  def copy_config_to_cache
    src = "#{@options.output_dir}/Config*.txt"
    dst = "#{@options.cache_dir}"
    files = Dir.glob(src)
    FileUtils.rmdir(dst)
    FileUtils.mkdir_p(dst)
    @log.info "Copying files to cache directory: '#{dst}'"
    FileUtils.cp(files,dst)
  end

  def get_vcenter_options(options,vcname)
    ret = nil
    filename = vcname.split('.').first
    path = File.dirname(options.config)
    fullpath = "#{path}/#{filename}.yml"
    if File.exist?(fullpath)
      @log.info("vCenter options file found at: '#{fullpath}'")
      begin
        opt = YAML.load(File.new(fullpath,'r'))
      rescue Exception => e 
        @log.error("There was an error processing vcenter_options '#{fullpath}'.")
        @log.error(e.message)
      end
      ret = opt ? opt : {}
    else      
      @log.info("No vCenter options file found at: '#{fullpath}'")
    end
    return ret
  end

  def collection_setup

    # Current Time for the vCenter Server
    current_time = @si.CurrentTime

    # Get Info about the vcenter configuration. Returns a Hash of options/config data
    begin
      @vcenter = get_vcenter(@content)
      @vcenter_name = "#{@vcenter["VirtualCenter.InstanceName"]}"
      @vcenter_uuid = @uuid
    rescue RbVmomi::VIM::NoPermission => e
      @log.error "#{e} User #{@user} must be given read access to vCenter"
      @exit_code = 8
      exit(@exit_code)
    end

    # Specific  vcenter options (by name)
    @vcenter_options = get_vcenter_options(@options,@vcenter_name)

    # Capture the metadata about each performance counter
    counter_descriptions   = @perfman.description.counterType  # Min, Max, Avg, etc.
    stat_type_descriptions = @perfman.description.statsType    # Absolute, Delta, Rat
    configured_intervals   = @perfman.historicalInterval       # What is enabled

    # What level is vCenter set to collect?
    @level = configured_intervals[0].level
    @sample_seconds = configured_intervals[0][:samplingPeriod]
    if @sample_seconds == 180 or @sample_seconds == 120
      @log.error("The vCenter Statistics 'Interval Duration' must not be set at 2 or 3 minutes.  Please configure at 1 or 5 minutes and retry." )
      raise VcenterConfigurationError.new("vCenter is not configured properly for use with Galileo Performance Explorer.")
    end

    # Capture data to disk
    write_string_to_file("#{@options.output_dir}/timestamp", file_timestamp(current_time))
    write_string_to_file("#{@options.output_dir}/uuid", @uuid)
    write_string_to_file("#{@options.output_dir}/InfoConfiguredIntervals.txt",configured_intervals.to_yaml)
    write_string_to_file("#{@options.output_dir}/InfoCounterDescriptions.txt",counter_descriptions.to_yaml)
    write_string_to_file("#{@options.output_dir}/InfoStatTypeDescriptions.txt",stat_type_descriptions.to_yaml)
    write_string_to_file("#{@options.output_dir}/InfoConfigFileState.txt",@config.to_yaml)

    # Capture the counters available - Meta for all counters
    # Absolute counters renamed to remove dups.  We don't use abosulte counters
    # for example mem.latency.average is a rate and an absolute
    @counters = collect_counters

    # Write out the counters that are available to this vcenter to: SupportedPerfCounters.csv
    counter_report

    # Filter by these counters.  See @collect
    filter = build_counters_filter

    # Determine the time Range from supplied options.  Must be under 20 mintues for performance.
    start_ts, end_ts = calculate_time_range(current_time, @options.seconds)

    # Set the chunk_size to the MaxQueryMetrics config value dynamically.
    chunk_size = get_config_value("config.vpxd.stats.maxQueryMetrics").to_i
    @chunk_size = ( chunk_size <= 0 ) ? 64 : chunk_size

    @log.info("          vCenter Name: #{@vcenter_name}")
    @log.info("          vCenter UUID: #{@vcenter_uuid}")
    @log.info("          vCenter Time: #{current_time}")
    @log.info("      Query Start Time: #{start_ts}")
    @log.info("        Query End Time: #{end_ts}")
    @log.info("  Daily Interval Level: #{@level}")
    @log.info("Detected Sample Period: #{@sample_seconds}")
    @log.info("     Max Query Metrics: #{@chunk_size} ( #{chunk_size} )")

    @excludes = make_excludes(@vcenter_options)

    # Inventory returns an array of Managened Entities by top down order.  DC:CL:RP:H:RP:VM
    # Iterating from 0-x will give the proper Parent/Child Relationship.  Do NOT reorder inventory!
    time = Time.now.to_i
    @log.info "Capture Object Inventory"
    @everything = all_entities()
    @orphan_hosts = hosts_not_in_a_cluster()
    @inventory = get_inventory(@root) + @orphan_hosts
    @log.info "End Capture Object Inventory #{Time.now.to_i-time} Seconds"
    set_quickinfo(@inventory)

    if @vsanrun
      # We have inventory get vsan if it's available. nil returned if nothing / error
      @vsandata = collect_vsan(start_ts,end_ts)
      write_vsan_metrics_to_disk unless @vsandata.nil?
    end

    # Build what metrics to pull by object.  Returns an array of RbVmomi::VIM::PerfQuerySpec objects
    time = Time.now.to_i
    @log.info "Prepare Query specifications"
    @query_specs = prepare_query_specs(@inventory, start_ts, end_ts, filter)
    ##Twrite_string_to_file("#{@options.output_dir}/InfoSpecDetails.txt",get_spec_details(@split_specs).to_yaml)
    @log.info "End Prepare Query specifications #{Time.now.to_i-time} Seconds"

  end

  def collect_vsan(start_ts,end_ts)
    ret =  {}
    begin
      ret[:space]  = get_vsan_space(@vsan,all_clusters())
      ret[:health] = get_vsan_health(@vsan,all_clusters())
      ret[:nodes]  = get_vsan_node(@vsan,all_clusters())
      ret[:perf]   = get_vsan_perf(@vsan,all_clusters(),start_ts,end_ts)
    rescue Exception => e
      @log.warn 'Unable to capture VSAN configuration. Please check vCenter setup: ' + e.message
      return nil
    end
    return ret
  end

  def query_spec_report(specs)
    total_metrics = 0
    specs.each{ |spec| total_metrics += spec.metricId.length.to_i}
    metric_count_by_type = specs.each_with_object(Hash.new) do |spec,ret|
      ret[spec.entity.class.to_s.to_sym] ||= []
      ret[spec.entity.class.to_s.to_sym] << spec.metricId.map{ |c| c.counterId }.uniq
    end
    ret = {}
    metric_count_by_type.each_pair{ |x,y| ret[x] = y.flatten.uniq.length }
    return {
      spec_list_total_length: specs.length,
               total_metrics: total_metrics,
          total_uniq_metrics: ret.values.inject{ |x,y| y+=x },
      unique_metrics_by_type: ret
    }
  end

  # Pull al config Value
  def get_config_value( config_name )
    config_value = get_vpx_settings( @content )[config_name]
    ret = config_value.nil? ? nil : config_value
    return ret
  end

  # Get Vpxd Settings into a hash
  def get_vpx_settings(content)
    settings = Hash.new(nil)
    content.setting.setting.map do |x|
      settings.store(x.key,x.value)
    end
    return settings
  end

  # Close out the vCenter connection(s)
  def close
    @connect.close

    total_threads = 1

    # Close stats threads
    @threadded_connections_stats.each do |c|
      c.close
      @log.debug "Closed statistics thread: #{c}"
      total_threads+=1
    end

    # Close config threads
    @threadded_connections_config.each do |c|
      c.close
      @log.debug "Closed config thread: #{c}"
      total_threads+=1
    end

    @log.info("Config and performance threads closed. (#{total_threads})")

  end

  def must_rerun
    return @rerun
  end

  private

  def get_readable_id(entity)
    return "#{entity.to_s.match(/\"(.*)\"/)[1]}"
  end

  def set_quickinfo(inventory)
    # Populate quickinfo for faster access to name, uuid and type.  Keyed by Entity Reference.
    # Memoize some info about each entity.  Too expensive to keep looking these up since they
    # traverse the network each time.
    time = Time.now.to_i
    @log.info("Populate Quick Info Stats")
    inventory.each do |obj|
      inv = obj.readable
      @quickinfo[inv] ||= {}
      @quickinfo[inv][:type]  = obj.type
      @quickinfo[inv][:class] = obj.class
      @quickinfo[inv][:id]    = obj.id
      @quickinfo[inv][:name]  = obj.name
      @quickinfo[inv][:uuid]  = obj.uuid
    end
    @log.info("Populate Quick Info Stats complete. (Total Entries: #{@quickinfo.length}, Seconds: #{Time.now.to_i-time})")
    return true
  end

  def write_vsan_metrics_to_disk
    start = Time.now.to_f
    @log.info "Write of VSAN statistics."
    file  = File.open("#{@options.output_dir}/TrendVsanStats.csv", "w")
    file << %w[Value TimeStampEpoch MetricId Unit Entity IntervalSecs Instance ].to_csv
    @vsandata[:perf].each do |cluster, metrics|
      metrics.each do |type, csv|
        csv.each do |data|
          props = data.props
          entity = props[:entityRefId].split(':',2).last
          sample = props[:sampleInfo].split(',')
          values = props[:value]
          values.each do |v|
            vals = v.values.split(',')
            int = v.metricId.metricsCollectInterval
            label = v.metricId.label
            metric = [type,label].join('.')
            vals.each_with_index do |o,i|
              ts = DateTime.strptime(sample[i],'%Y-%m-%d %H:%M:%S').strftime("%s")
              file << [ o, ts, metric, '', cluster, int, entity].to_csv
            end
          end
        end
      end
    end
    file.close
    @log.info "End Write of VSAN statistics. #{(Time.now.to_f - start).round(4)}"
    return nil
  end

  def get_spec_details(split_specs)
    see_specs = {}
    split_specs.each_pair do |type,specs|
      see_specs[type] ||= []
      specs.each do |spec|
        inv = get_readable_id(spec.entity)
        quick = @quickinfo[inv]
        see_specs[type] << {
          :type    => quick[:class],
          :name    => quick[:name],
          :len     => spec.metricId.length,
          :start   => spec.startTime,
          :end     => spec.endTime,
          :metric  => spec.metricId.map{ |x| x.props }
        }
      end
    end
    return see_specs
  end

  def collect_from_single_value(val, name, uuid, type, parent_input='', key='')

    if !parent_input.to_s.empty? and !key.to_s.empty?
      prefix  = "#{parent_input}.#{key}"
    elsif parent_input.to_s.empty?
      prefix  = key.to_s
    elsif key.to_s.empty?
      prefix  = parent_input.to_s
    end

    depth = caller.length

    @log.debug("Recursion level detail: (#{depth}/#{type}/#{name}/#{uuid}/#{parent_input}.#{key}")

    ret = Array.new

    if parent_input =~ /^config\.hardware\.device\.\d+\.backing\.parent/;
      @log.debug("Skipping config value: (#{depth}/#{type}/#{name}/#{uuid}/#{parent_input}.#{key}")
      return ret
    end

    if val.is_a? String or val.is_a? Fixnum or val.is_a? FalseClass or val.is_a? TrueClass or val.is_a? Integer
      ret = [[type, name, uuid, "#{prefix}", encode_str(val)]]
    elsif val.is_a? RbVmomi::VIM::OptionValue
      ret = [[type, name, uuid, "#{prefix}.#{val.key}", encode_str(val.value)]]
    elsif val.is_a? RbVmomi::BasicTypes::DataObject or val.is_a? Hash
      props = val
      props = val.props if val.is_a? RbVmomi::BasicTypes::DataObject
      props.each do |key, value|
        ret += collect_from_single_value(value, name, uuid, type, prefix, key)
      end
    elsif val.is_a? Time
      ret = [[type, name, uuid, "#{prefix}", val.to_i]]
    elsif val.is_a? Array
      return [] if val.empty?
      val.each_index do |i|
        ret += collect_from_single_value(val[i], name, uuid, type, prefix, i.to_s)
      end
    elsif val.is_a? RbVmomi::VIM::ManagedEntity or val.is_a? RbVmomi::VIM::ExtensibleManagedObject or val.is_a? RbVmomi::VIM::ManagedObject
      ret = [[type, name, uuid, "#{prefix}", encode_str(val.to_s)]]
    else
      @log.warn("Found an unexpected datatype in when gathering config (#{prefix}): #{val.class}")
    end

    return ret
  end

  def encode_str(val)
    return val.to_s.gsub("\n","\\n")
  end

  # Return the vcenter inventory from the root folder
  def all_entities
    ret = Set.new
    ret += get_entity(@root,[], true)
    return ret
  end
  
  def invget(type=nil)
    @everything.select{ |o| o.class.to_s.downcase.to_sym == type }
  end

  def hosts_not_in_a_cluster
    ret = []
    clusters = invget(:clustercomputeresource)
    hosts = invget(:hostsystem)
    hic = Set.new
    clusters.map{ |c| hic += get_entity(c, ['HostSystem'], true) }
    (hosts - hic.to_a).each do |host|
      ret << Inventory.new(host,@log)
      get_entity(host,['VirtualMachine'],true).map{ |vm| ret << Inventory.new(vm, @log)}
    end
    return ret
  end
  
  # Create the inventory tree and config data of that inventory.
  # The inventory array input here can never be reordered
  def inventory_tree(inventory,config,vcenter_name,vcenter_uuid)
    rows = []
    parent = Hash.new(Array.new(3))
    name, id, uuid, pname, pid, puuid, type = ""

    # Maunually Add the Vcenter
    pinfo = parent['vcenter']
    rows << [vcenter_name,vcenter_uuid,vcenter_uuid,pinfo,'vcenter'].flatten
    parent['vcenter'] = [vcenter_name,vcenter_uuid,vcenter_uuid]

    inventory.each do |obj|

      name  = obj.name
      type  = obj.class
      id    = obj.id
      uuid  = obj.uuid

      @log.debug "Adding to inventory Tree: #{type}/#{name} (#{uuid})"

      case type
        when 'Datacenter'
          pinfo = parent['vcenter']
        when 'ClusterComputeResource','Datastore','Network'
          pinfo = parent['Datacenter']
        when 'ResourcePool'
          pinfo = parent['ClusterComputeResource']
        when 'HostSystem'
          if obj.entity.parent.class.to_s == "ComputeResource"
            pi = find_parent_of_type(obj.entity,'Datacenter')
            pi = Inventory.new(pi,@log)
            pinfo = [pi.name,pi.id,pi.uuid]
          else
            pinfo = parent['ClusterComputeResource']
          end
        when 'VirtualMachine'
          pinfo = parent['HostSystem']
      end

      parent[type] = [name,id,uuid]
      rows << [name,id,uuid,pinfo,type].flatten

    end

    write_csv(%w[Name Id Uuid ParentName ParentId ParentUuid Type],rows,"ConfigInventory.txt")

  end

  def find_parent_of_type(obj,type)
    parent = obj.parent
    return nil if parent.nil?
    return parent if parent.class.to_s == type
    find_parent_of_type(parent,type)
  end

  def config_files
    @quickinfo.values.map{ |o| o[:class] }.uniq
  end

  def config_files_open(files)
    ret = {}
    header = %w[Type Name UUID Metric Value]
    files.each do |type|
      fname = "#{@options.output_dir}/Config#{type}.txt"
      ret[type] = CSV.open( fname, "w", { write_headers: true, headers: header, force_quotes: true } )
    end
    return ret
  end

  def config_files_close(files)
    files.values.each do |file|
      file.close
      @log.info "Writing file: '#{file.path}'"
    end
    return nil
  end

  def write_rows_as_csv(file,rows)
    rows.each do |row|
      file << row
    end
  end

  def collect_all_config(config)

    files = config_files_open(config_files)
    total_configs = config.keys.length
    c=0

    config.each_pair do |obj,config_hash|
      c+=1
      loopstart = Time.now.to_f
      start = Time.now.to_f
      inv   = get_readable_id(obj)
      type = @quickinfo[inv][:class]
      name = @quickinfo[inv][:name]
      uuid = @quickinfo[inv][:uuid]
      file = files[type]
      rows = craw_single_config( config_hash, name, uuid, type, obj )
      write_rows_as_csv(file,rows)
      @log.debug "Config Loop #{c} of #{total_configs} took #{Time.now.to_f - loopstart}"
    end

    config_files_close(files)

    return nil

  end

  def craw_single_config( config, name, uuid, type, obj )
    ret = []
    begin
      ret += collect_from_single_value(config, name, uuid, type)
    rescue SystemStackError => e
      @log.error("Failed for object: #{obj.class.to_s}/#{obj.name}")
      @log.error(e.message)
      e.backtrace[-10..-1].each{ |level| @log.error(level) }
      @log.error("Rerun with --debug flag to capture stack trace.") unless @debug
      exit
    end
    return ret
  end

  # Create csv files from header,rows
  def write_csv(header,rows,filename)
    outfile  = "#{@options.output_dir}/#{filename}"
    @log.info "Writing file '#{outfile}' (#{rows.length})"
    output = CSV.open( outfile, "w", { write_headers: true, headers: header, force_quotes: true } )
    rows.each{ |row| output << row }
    output.close
  end

  def get_inventory(root)
    ret = []
    excluded_vms = []
    @log.warn "vCenter option 'collect_vms' is set to false. No Guest data will be collected." if exclude_all_vms?
    get_entity(root,['Datacenter'],true).each do |dc|
      ret << Inventory.new(dc,@log)
      get_entity(dc,['Datastore'],true).each{ |ds| ret << Inventory.new(ds,@log) }
      get_entity(dc,['Network'],true).each{ |net| ret << Inventory.new(net,@log) }
      get_entity(dc,['ClusterComputeResource'],true).each do |cl|
        ret << Inventory.new(cl,@log)
        get_entity(cl,['ResourcePool'],false).each{ |clpool| ret << Inventory.new(clpool,@log) }
        get_entity(cl,['HostSystem'],false).each do |host|
          ret << Inventory.new(host,@log)
          get_entity(host,['ResourcePool'],false).each{ |hostpool| ret << Inventory.new(hostpool,@log) }
          next if exclude_all_vms?
          get_entity(host,['VirtualMachine'],false).each do |vm|
            if should_exclude?(vm)
              excluded_vms << vm.name
            else
              ret << Inventory.new(vm,@log)
            end
          end
        end
      end
    end
    if excluded_vms.length > 0 then 
      @log.warn "#{excluded_vms.length} VM guest(s) excluded from collection by name in vCenter options file."
    end

    debug_inventory(ret)
    return ret
  end

  def debug_inventory(ret)
    # Print details if this is debug mode
    if @debug
      @log.debug("Inventory Listing...")
      ret.each do |inv|
        @log.debug("Found Inventory: #{inv.name}/#{inv.readable}")
      end
    end
  end

  def exclude_all_vms?
    return false if @vcenter_options.nil?
    return false if @vcenter_options.is_a?(Array)
    if @vcenter_options['collect_vms'] == true or @vcenter_options['collect_vms'].nil?
      return false
    end
    return true
  end

  # Check if we are exclude this type by it's name (regexp)
  def should_exclude?(ent)
    return false if @excludes.nil? or @excludes.is_a?(Array)
    match = ent.name.match(@excludes)
    ret = match.nil? ? false : true
    return ret
  end

  # Get config properties for each inventory object
  def get_config(inventory,props)
    ret = Hash.new
    delta_quant = (inventory.length.to_f / @options.num_threads.to_f).ceil
    threads = Array.new(@options.num_threads)
    config = Array.new(@options.num_threads)

    0.upto(@options.num_threads-1) do |thread_id|
      threads[thread_id]  = Thread.new(thread_id) do |thr_id|
        start = Time.now
        index_start = thr_id*delta_quant
        index_end = index_start + delta_quant - 1
        if @threadded_connections_config[thr_id].nil?
          @log.debug "Start Property Collect Thread #{thr_id}"
          @threadded_connections_config[thr_id] = RbVmomi::VIM.connect(
            host: @options.server,
            user: @options.user,
            password: @options.password,
            insecure: true, debug: @options.vcdebug
          )
          @threadded_connections_config[thr_id].profiling = true
          @profiles["config-#{thr_id}"] = @threadded_connections_config[thr_id].profile_summary if @vcprofile
        end
        config[thr_id] = gather_config(@threadded_connections_config[thr_id], index_start, index_end, inventory, props)
        @log.debug "End Property Collect Thread #{thr_id} (Seconds: #{Time.now - start})"
      end
    end

    threads.each do |thread_id|
      joined = thread_id.join
      @log.debug("Waiting for config thread: #{joined}")
    end

    ret = config.each_with_object(Hash.new){ |config,hash| hash.update(config) }

    return ret
  end

  # Pull the config
  def gather_config(conn, index_start, index_end, inventory, props)
    ret = Hash.new
    inventory_part = inventory[index_start..index_end]
    unless inventory_part.nil? or inventory_part.empty?
      inventory_part.each do |obj|
        @log.debug "Get config from vcenter for #{obj.type}/#{obj.name}/#{obj.readable}/#{obj.uuid}"
        entity = obj.entity
        if props[obj.type]
          ret[entity] = call_props(conn,create_prop_filter(obj,false,props[obj.type].clone))
        else
          ret[entity] = call_props(conn,create_prop_filter(obj))
        end
      end
    end
    return ret
  end

  # Add call_props to wrap get_props in rescue
  def call_props(conn,filter)
    ret = {}
    begin
      ret = get_props(conn,filter)
    rescue SystemStackError => e
      info = filter[:objectSet].first[:obj]
      @log.warn "(Depth: #{caller.length}) Cannot obtain config data: #{e.message}. Obj: #{info.name}"
    end
    return ret
  end

  # Get the configuration for the entity using the propertly collector
  def get_props(conn,filter)
    propcoll = conn.serviceInstance.content.propertyCollector
    props = {}
    begin
      results  = propcoll.RetrievePropertiesEx( { specSet: [filter], options: { maxObjects: 10000 } } )
      unless results.nil?
        while results.token
          props << results.objects.map{ |o| o.propSet.map{ |p| { p.name => p.val } } }
          results = propcoll.ContinueRetrievePropertiesEx( { token: results.token } )
        end
        results.objects.map{ |o| o.propSet.each{ |p| props.store(p.name,p.val) } }
      end
    rescue RbVmomi::VIM::InvalidProperty => e
      @exit_code = 4 unless @exit_code > 4
      @log.warn("Invalid property #{e.name} for #{filter[:objectSet][0][:obj].name}")
      filter[:propSet][0][:pathSet].delete(e.name)
      props = get_props(filter)
    end
    return props
  end

  # Create the filter for the propertly collector
  def create_prop_filter(obj,all=true,path=[])
    filter = {
      objectSet: [ { obj: obj.entity } ],
      propSet: [
        { all: all, pathSet: path, type: obj.class },
      ], reportMissingObjectsInResults: true
    }
    return filter
  end

  # Call to get the obj using containerview
  def get_entity(obj,type=[],recursive=false)
    @viewman.CreateContainerView( { type: type, container: obj, recursive: recursive } ).view.map{ |o| o }
  end

  # Report on the counters found on this system
  def counter_report
    outfile = "#{@options.output_dir}/InfoSupportedPerfCounters.txt"
    counter_report = "id,name,group,level,device_level,stats_type,sumary\n"
    @counters.each_pair do |name,val|
      counter_report << "#{val[:key]},#{name},#{val[:group]},#{val[:level]},#{val[:devicelevel]},#{val[:statsType]},#{val[:summary]}\n"
    end
    write_string_to_file(outfile, counter_report)
  end

  # Use the @collect name values to build an array of counter id's (@counters)
  # Compare the yml collect values to what's on the system.
  # If there is a discrepency then log and error and skip it
  def build_counters_filter
    ret = Hash.new
    @collect.each_pair do |type,name|
      @log.debug "Build metric filter for #{type}"
      id_list ||= Array.new
      name.each do |val|
        if @counters[val] == false
          @log.warn("Specified counter #{type}/#{val} is not valid and is being skipped.")
          next
        end
        if @collect[type].include?("AUTO")
          id_list = [ "AUTO" ]
        else
          id_list <<  @counters[val][:key]
        end
      end
      ret[type] = id_list.flatten.sort
    end
    return ret
  end

  def get_vcenter(content)
    vcenter_props = content.about.props
    vcenter_options = Hash.new
    content.setting.setting.each do |opt|
      vcenter_options[opt.props[:key]] = opt.props[:value]
    end
    ret = vcenter_props.merge(vcenter_options)
    vcenter_name = "#{ret["VirtualCenter.InstanceName"]}"
    vcenter_uuid = ret[:instanceUuid].downcase
    rows = []
    ret.each_pair do |key,val|
      rows << ["Vcenter",vcenter_name,vcenter_uuid,key,val]
    end
    write_csv(%w[Type Name UUID Metric Value], rows, "ConfigVcenter.txt")
    return ret
  end

  def flatten_stats(stats)
    data = Hash.new
    stats.each_with_index do |spec,i|
      entity=spec.entity
      data[entity] ||= Hash.new
      data[entity][:sample] ||= []
      data[entity][:sample] << spec.sampleInfo if data[entity][:sample].empty?
      data[entity][:value] ||= []
      data[entity][:value] << spec.value
    end
    ret = []
    data.each do |ent,vals|
      ret << RbVmomi::VIM::PerfEntityMetric({
        entity: ent,
        value: vals[:value].flatten,
        sampleInfo: vals[:sample].flatten
      })
    end
    return ret
  end

  # Ouptut the trend data
  def save_trend_data(stats)

    by_key     = counters_by_key
    startts    = Time.now.to_i
    open_files = Hash.new
    stats      = flatten_stats(stats)

    stats.each_with_index do |stat|

      timestamps = stat.sampleInfo.map{|s| s.timestamp}
      intervals  = stat.sampleInfo.map{|s| s.interval}
      entity     = stat.entity
      inv        = get_readable_id(entity)
      el_name    = @quickinfo[inv][:name]
      stat_type  = @quickinfo[inv][:class]
      el_uuid    = @quickinfo[inv][:uuid]
      file       = open_files[stat_type]

      if file.nil?
        file  = File.open("#{@options.output_dir}/Trend#{stat_type}.csv", "w")
        file << "\"Value\",\"TimeStampEpoch\",\"MetricId\",\"Unit\",\"Entity\",\"IntervalSecs\",\"Instance\"\n"
        open_files[stat_type] = file
      end

      stat.value.sort{|x,y| x.id.counterId <=> y.id.counterId}.each do |val|
        key = val.id.counterId
        name = by_key[key]
        counter = @counters[name]
        val.value.each_index do |i|
          line  = Array.new
          line << val.value[i]
          line << timestamps[i].to_i
          line << counter[:name]
          line << counter[:unit]
          line << el_uuid
          line << intervals[i]
          line << val.id.instance
          file << line.map{|v| "\"#{v}\""}.join(",")
          file << "\n"
        end
      end
    end

    open_files.values.each do |file|
      @log.info "Writing file '#{file.path}'"
      file.close
    end

    endts = Time.new.to_i
    @log.info("Save trend took #{endts-startts}")
  end

  def counters_by_key
    newa=[]
    @counters.each_pair.map{ |k,v| v[:key].each{ |id| newa[id] = k } }
    return newa
  end

  # Make a clone copy of the split_specs [Hash]
  def clone_specs(specs)
    ret = Array.new
    specs.each do |spec|
      ret << spec.clone
    end
    return ret
  end

  # Start Threads to collect performance Stats
  def collect_statistics(specs)

    # Clone this so we can rerun if needed
    list        = specs.clone
    stats       = Array.new(@options.num_threads)
    threads     = Array.new(@options.num_threads)
    thread_size = (list.length.to_f / threads.length.to_f).ceil
    thread_id   = 0
    start       = Time.now

    @log.info("Total metrics to collect: #{list.length}")
    @log.info("Requested threads: #{threads.length}")

    # Slice up specs by thread count
    slices = threads.map.each_with_index{ |s,i| list.shift(thread_size) }

    # Create a thread, one for each managed entity.
    0.upto(threads.length-1) do |thr_id|
      threads[thread_id] = Thread.new(thread_id) do |thr_id|
        start = Time.now
        @log.info("Start trend thread #{thr_id}, #{slices[thr_id].length} metric(s)")
        if @threadded_connections_stats[thr_id].nil?
          @threadded_connections_stats[thr_id] = RbVmomi::VIM.connect(
            host: @options.server,
            user: @options.user,
            password: @options.password,
            insecure: true, debug: @options.vcdebug
          )
          @threadded_connections_stats[thr_id].profiling = true
          @profiles["trend-#{thr_id}"] = @threadded_connections_stats[thr_id].profile_summary if @vcprofile
        end
        stats[thr_id] = gather_stats(@threadded_connections_stats[thr_id], slices[thr_id], thr_id)
      end
      thread_id += 1
    end

    # Wait here for performance threads to finish.
    threads.each{ |thread_id| thread_id.join }

    # If any thread reported a failure then close and schedule rerun
    if @rerun
      @log.warn "Rerun is required.  Metrics to retry: #{@rerun_list.length}"
      close
    end

    ret = stats.flatten
    @log.info "Collection finished.  Total performance statistics returned: #{ret.length}."
    @log.debug "End collecting trend data (Seconds: #{Time.now - start}, total: #{ret.length})"
    @exit_code = 0
    return ret
  end

  # Define specs to collect for each inventory object
  def prepare_query_specs(inventory, starttime, endtime, filter)

    @log.info("Creating query specifications for inventory objects.")

    query_specs = Array.new
    remember_filter = Hash.new(false)

    inventory.each do |obj|

      by_key = counters_by_key
      inv = obj.readable

      type = @quickinfo[inv][:type]

      case filter[type]

        when [ "AUTO" ]
          if remember_filter[type] == false
            @log.info("Query vCenter (AUTO) for performance counters for type: #{obj.class}")
            autospecs = @perfman.QueryAvailablePerfMetric( { entity: obj.readable, beginTime: starttime, endtime: endtime, intervalId: @sample_seconds })
            filter[:selected] = autospecs
            remember_filter[type] = autospecs
          else
            filter[:selected] = remember_filter[type]
          end

        when nil
          @log.debug("Skipping metric build for type #{type}")

        else
          @log.debug("Using SPECIFIED metrics in config file for type: #{obj.class}")
          filter[:selected] = filter[type].map do |id|
            instance = by_key[id].match(/^cpu\./) ? '' : '*'
            RbVmomi::VIM::PerfMetricId( counterId: id, instance: instance )
          end

      end

      unless filter[type].nil?
        while filter[:selected].length > 0
          entity_id = obj.readable
          metric_id = filter[:selected].shift
          query_specs << [ entity_id, starttime, endtime, metric_id ]
        end
      end
    end

    @log.debug "PerfQuerySpec size: #{query_specs.length}"

    return query_specs
  end

  def make_query_spec(specs)
    ret = []
    grouped = specs.group_by{ |s| s.first }
    grouped.each_key do |key|
      entity    = grouped[key].first[0]
      starttime = grouped[key].first[1]
      endtime   = grouped[key].first[2]
      chunk     = grouped[key].map{ |s| s[3] }
      ret << RbVmomi::VIM::PerfQuerySpec(
        :entity     => entity,
        :intervalId => @sample_seconds.to_s,
        :startTime  => starttime,
        :endTime    => endtime,
        :metricId   => chunk
      )
    end
    return ret
  end

  # Return counter meta info
  def collect_counters
    system_counters = @perfman.perfCounter
    ret = Hash.new(false)
    system_counters.each do |counter|
      name ||= Array.new
      name << counter.groupInfo.key.downcase
      name << counter.nameInfo.key.downcase
      name << counter.rollupType.downcase
      #name << counter.statsType
      key=name.join(".")
      if ret[key]
        @log.debug "Duplicate metric: #{key} (#{ret[key][:key].join(",")}), Adding: #{counter.key}" if ret[key]
        ret[key][:key] << counter.key
        next
      end
      ret[key] ||= Hash.new
      ret[key][:key]     ||= []
      ret[key][:key]      << counter.key
      ret[key][:name]      = name[0..2].join(".")
      ret[key][:statsType] = counter.statsType
      ret[key][:summary]   = counter.nameInfo.summary
      ret[key][:label]     = counter.nameInfo.label
      ret[key][:group]     = counter.groupInfo.label
      ret[key][:unit]      = counter.unitInfo.key
      ret[key][:level]     = counter.level
      ret[key][:devicelevel] = counter.perDeviceLevel
    end
    return ret
  end

  # Pull the stats
  def gather_stats(conn, query_specs, type)
    perf = conn.serviceInstance.content.perfManager
    data = Array.new
    data = collect_performance_data(perf,query_specs,type)
    return data
  end

  def collect_performance_data(perf, query_specs, type)
    error_count = 0
    data = Array.new
    start_count = query_specs.length.to_f
    threshold = 100

    # Loop through each query_spec; shift off a fetch size and process
    while query_specs.length > 0
      spec_slice = query_specs.shift(@chunk_size)
      save_slice = clone_specs(spec_slice)
      specs = make_query_spec(spec_slice)
      remain = (query_specs.length / start_count * 100).to_i + 1
      begin
        count = specs.map{ |x|  x[:metricId].length }.inject{ |x,y| x += y }
        if remain <= threshold
          @log.info("Trend Thread #{type}: #{remain}% remaining.")
          threshold = threshold - 25
        end
        data << perf.QueryPerf( { querySpec: specs })
      rescue RbVmomi::Fault => e
        @rerun = true
        @log.warn("Adding #{save_slice.length} metrics to rerun list.")
        @rerun_list += save_slice
        @exit_code = 8 unless @exit_code > 8
        @log.error("Error: Unable to collect thread ##{type} trend data: #{e}" )
      end
    end
    return data
  end

  def print_specs(specs)
    specs.each.map do |x|
      inv = get_readable_id(x.entity)
      [
        @quickinfo[inv][:type],
        @quickinfo[inv][:class],
        @quickinfo[inv][:name],
        x.startTime,
        x.endTime,
        x.intervalId,
        x.metricId.map{ |x| x}
      ]
    end
  end

  # Return an array of specs from a single, splitting out by all metricIds
  def fragment_spec(spec)
    new_specs = []
    spec.metricId.each do |metric|
      new_specs << RbVmomi::VIM::PerfQuerySpec(
            entity: spec.entity,
        intervalId: spec.intervalId,
         startTime: spec.startTime,
           endTime: spec.endTime,
          metricId: [ metric ]
      )
    end
    return new_specs
  end

  def calculate_time_range(current_time, seconds)
    # Create a start and end ts all objects and then cluster -5 minutes
    end_ts           = (current_time).strftime("%Y-%m-%dT%H:%M:%SZ")
    start_ts         = (current_time - seconds).strftime("%Y-%m-%dT%H:%M:%SZ")
    return start_ts, end_ts
  end

  def write_string_to_file(filename, str)
    @log.info "Writing file '#{filename}'"
    output = File.open(filename, "w")
    output << str
    output.close
  end

  def file_timestamp(ts=Time.now)
    current_time = ts.utc
    runtime_date = current_time.strftime("%Y") + current_time.strftime("%m") + current_time.strftime("%d")
    runtime_time = current_time.strftime("%H") + current_time.strftime("%M") + current_time.strftime("%S")
    return "#{runtime_date}.#{runtime_time}.GMT"
  end

end

# Execute main
def main()

  # Capture ARGV options
  options = Options.new(ARGV)

  # Sent log for this execution to STDOUT and a uniq name using 
  short_server = options.server.split('.').first
  log_name  = "#{options.output_dir}/LOG.#{short_server}.txt"
  File.delete(log_name) if File.exist? log_name
  log_file  = File.open(log_name, "w")
  log_paths = MultiDelegator.delegate(:write, :close).to(log_file,STDOUT)
  log       = Logger.new(log_paths)
  log.level = Logger::INFO
  log.level = Logger::DEBUG if options.debug

  # Call the Collector
  begin
    vmware = VMWareCollector.new(options,log)
  rescue RbVmomi::Fault => e
    log.error e.message
    exit 1
  end

  # Exit here for a test connection
  if options.test_run
    log.info "Successful Login"
    vmware.close
    exit 0
  end

  # Otherwise start collection
  rerun_count = 1
  start_time = Time.now.to_i
  log.info "Starting Collection"
  begin
    vmware.collect
    while vmware.must_rerun and rerun_count <= options.rerun_tries
      vmware.last_try = true if rerun_count == options.rerun_tries
      log.warn("")
      log.warn("Performance Collection Failed.  Attempting rerun ##{rerun_count}")
      log.warn("Last retry attempt.") if vmware.last_try
      log.warn("")
      rerun_count += 1
      sleep 30
      vmware.reconnect
      vmware.collect
    end
  rescue Exception => e
    log.error("Collection Failed: #{e.message}")
    e.backtrace.each{ |line| log.error(line) }
  ensure
    vmware.close
    end_time = Time.now.to_i
    log.info "Ending Collection (#{end_time - start_time} Seconds)"
  end

  # Exit with the max code 0 ok, 4 warn, 8 crticial
  exit_code = vmware.exit_code.to_i
  log.info "Exit code: #{exit_code}"
  exit(exit_code)

end

# Execute Main
main
