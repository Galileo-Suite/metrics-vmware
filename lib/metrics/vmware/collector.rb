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
                    :connection, 
                    :options,
                    :si,
                    :content,
                    :perfman,
                    :viewman,
                    :uuid,
                    :root

        def initialize
            @options = get_vcenter_options()
            @log = Logger.new(STDOUT)
            @connect = make_connection()
            ap @si
        end

        def connection_setup
            @svci,         = @connect.serviceInstance
            @content    = @si.content
            @perfman    = @content.perfManager
            @viewman    = @content.viewManager
            @uuid       = @content.about.props[:instanceUuid].downcase
            @root       = @content.rootFolder
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
            @connection = RbVmomi::VIM.connect(
                host: options.server,
                user: options.user,
                password: options.password,
                insecure: true, debug: options.vcdebug
            )
        end

        def collect
            log.info("Starting VMware Collector")
        end

    end

end