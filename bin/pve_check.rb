#! /usr/bin/env ruby
# frozen_string_literal: true

require 'optparse'
require 'net/https'
require 'json'
require 'date'

version = 'v0.2.4'

# optparser
banner = <<~HEREDOC
  check_pve #{version} [https://gitlab.com/6uellerBpanda/check_pve]\n
  This plugin checks various parameters of Proxmox Virtual Environment via API(v2)\n
  Mode:
    Cluster:
      cluster         Checks quorum of cluster
    Node:
      smart           Checks SMART health of disks
      updates         Checks for available updates
      subscription    Checks for valid subscription
      services        Checks if services are running
      storage         Checks storage usage in percentage
      cpu             Checks CPU usage in percentage
      memory          Checks Memory usage in gigabytes
      io_wait         Checks IO wait in percentage
      net_in          Checks inbound network usage in kilobytes
      net_out         Checks outbound network usage in kilobytes
      ksm             Checks KSM sharing usage in megabytes
    VM:
      vm_cpu          Checks CPU usage in percentage
      vm_disk_read    Checks how many kb last 60s was read (timeframe: hour)
      vm_disk_write   Checks how many kb last 60s was written (timeframe: hour)
      vm_net_in       Checks incoming kb from last 60s (timeframe: hour)
      vm_net_out      Checks outgoing kb from last 60s (timeframe: hour)

  Usage: #{File.basename(__FILE__)} [mode] [options]
HEREDOC

options = {}
OptionParser.new do |opts| # rubocop:disable  Metrics/BlockLength
  opts.banner = banner.to_s
  opts.separator ''
  opts.separator 'Options:'
  opts.on('-s', '--address ADDRESS', '-H', 'PVE host address') do |s|
    options[:address] = s
  end
  opts.on('-k', '--insecure', 'No SSL verification') do |k|
    options[:insecure] = k
  end
  opts.on('-m', '--mode MODE', 'Mode to check') do |m|
    options[:mode] = m
  end
  opts.on('-n', '--node NODE', 'PVE Node name') do |n|
    options[:node] = n
  end
  opts.on('-u', '--username USERNAME', 'Username with auth realm e.g. monitoring@pve') do |u|
    options[:username] = u
  end
  opts.on('-p', '--password PASSWORD', 'Password') do |p|
    options[:password] = p
  end
  opts.on('-w', '--warning WARNING', 'Warning threshold') do |w|
    options[:warning] = w
  end
  opts.on('-c', '--critical CRITICAL', 'Critical threshold') do |c|
    options[:critical] = c
  end
  opts.on('--name NAME', 'Name for storage') do |name|
    options[:name] = name
  end
  opts.on('-i', '--vmid VMID', 'Vmid of lxc,qemu') do |i|
    options[:vmid] = i
  end
  opts.on('-t', '--type TYPE', 'VM type lxc or qemu') do |t|
    options[:type] = t
  end
  opts.on('-x', '--exclude EXCLUDE', 'Exclude (regex)') do |x|
    options[:exclude] = x
  end
  opts.on('--timeframe TIMEFRAME', 'Timeframe for vm checks: hour,day,week,month or year') do |timeframe|
    options[:timeframe] = timeframe
  end
  opts.on('--cf CONSOLIDATION_FUNCTION', 'RRD cf: average or max') do |cf|
    options[:cf] = cf
  end
  opts.on('-v', '--version', 'Print version information') do
    puts "check_pve #{version}"
  end
  opts.on('-h', '--help', 'Show this help message') do
    puts opts
  end
  ARGV.push('-h') if ARGV.empty?
end.parse!

# check pve
class CheckPve
  def initialize(options) # rubocop:disable Metrics/MethodLength
    @options = options
    init_arr
    cluster
    smart
    updates
    services
    subscription
    cpu
    mem
    ksm
    io_wait
    storage
    net_in
    net_out
    vm_disk_write
    vm_disk_read
    vm_cpu
    vm_net_in
    vm_net_out
  end

  def init_arr
    @perfdata = []
    @message = []
    @critical = []
    @warning = []
    @okays = []
  end

  #--------#
  # HELPER #
  #--------#

  # define some helper methods for naemon with appropriate exit codes
  def ok_msg(message)
    puts "OK - #{message}"
    exit 0
  end

  def crit_msg(message)
    puts "Critical - #{message}"
    exit 2
  end

  def warn_msg(message)
    puts "Warning - #{message}"
    exit 1
  end

  def unk_msg(message)
    puts "Unknown - #{message}"
    exit 3
  end

  # helper to convert bytes
  def convert_bytes_to_unit(data:, unit:)
    case unit
    when 'kb' then @usage = data.to_i / 1024
    when 'mb' then @usage = data.to_i / 1024 / 1024
    when 'gb' then @usage = data.to_i / 1024 / 1024 / 1024
    end
  end

  # check only one value
  def check_single_data(data:, message:)
    crit_msg(message) if data
  end

  # check only two values
  def check_multiple_data(data:, warn_msg:, ok_msg:)
    if data
      warn_msg(warn_msg)
    else
      ok_msg(ok_msg)
    end
  end

  # helper for excluding
  def exclude(data:, value:)
    data.delete_if { |item| /#{@options[:exclude]}/.match(item[value]) }
  end

  # generate perfdata
  def build_perfdata(perfdata:)
    @perfdata << "#{perfdata};#{@options[:warning]};#{@options[:critical]}"
  end

  # build service output
  def build_output(msg:)
    @message = msg
  end

  # helper for threshold checking
  def check_thresholds(data:)
    if data > @options[:critical].to_i
      @critical << @message
    elsif data > @options[:warning].to_i
      @warning << @message
    else
      @okays << @message
    end
    # make the final step
    build_final_output
  end

  # mix everything together for exit
  def build_final_output
    perf_output = " | #{@perfdata.join(' ')}"
    if @critical.any?
      crit_msg(@critical.join(', ') + perf_output)
    elsif @warning.any?
      warn_msg(@warning.join(', ') + perf_output)
    else
      ok_msg(@okays.join(', ') + perf_output)
    end
  end

  #----------#
  # API AUTH #
  #----------#

  def url(path:, req: 'get') # rubocop:disable Metrics/MethodLength
    uri = URI("https://#{@options[:address]}:8006/#{path}")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE if @options[:insecure]
    if req == 'post'
      request = Net::HTTP::Post.new(uri.request_uri)
      request.set_form_data('username' => @options[:username].to_s, 'password' => @options[:password].to_s)
    else
      fetch_cookie
      request = Net::HTTP::Get.new(uri.request_uri)
      request['cookie'] = @token
    end
    @response = http.request(request)
  rescue StandardError => e
    unk_msg(e)
  end

  # check http response
  def check_http_response
    unk_msg(@response.message).to_s if @response.code != '200'
  end

  # init http req
  def http_connect(path:, req: 'get')
    url(path: path, req: req)
    check_http_response
  end

  # get cookie
  def fetch_cookie
    http_connect(path: 'api2/json/access/ticket', req: 'post')
    @token = "PVEAuthCookie=#{JSON.parse(@response.body)['data']['ticket']}"
  end

  #--------#
  # CHECKS #
  #--------#

  ###--- CLUSTER CHECK ---###
  def cluster
    return unless @options[:mode] == 'cluster'
    http_connect(path: 'api2/json/cluster/status')
    cluster = JSON.parse(@response.body)['data'].first
    check_multiple_data(
      data: cluster['quorate'] != 1,
      warn_msg: "#{cluster['name'].upcase}: Cluster not ready - no quorum",
      ok_msg: "#{cluster['name'].upcase}: Cluster ready - quorum is ok"
    )
  end

  ###--- SMART CHECK ---###
  def smart
    return unless @options[:mode] == 'smart'
    http_connect(path: "api2/json/nodes/#{@options[:node]}/disks/list")
    unhealthy = JSON.parse(@response.body)['data'].reject { |item| item['health'] == 'PASSED' }
    exclude(data: unhealthy, value: 'devpath') unless @options[:exclude].to_s.empty?
    warn_msg(unhealthy.map { |item| "#{item['model']}:#{item['used']}-#{item['devpath']} SMART error detected" }.join(', ')) if unhealthy.any?
    ok_msg('No SMART errors detected')
  end

  ###--- UPDATE CHECK ---###
  def updates
    return unless @options[:mode] == 'update'
    http_connect(path: "api2/json/nodes/#{@options[:node]}/apt/update")
    check_multiple_data(
      data: JSON.parse(@response.body)['data'].any?,
      warn_msg: 'New updates available',
      ok_msg: 'System up to date'
    )
  end

  ###--- SERVICES CHECK ---###
  def services
    return unless @options[:mode] == 'services'
    http_connect(path: "api2/json/nodes/#{@options[:node]}/services")
    services_down = JSON.parse(@response.body)['data'].reject { |item| item['state'] == 'running' }
    exclude(data: services_down, value: 'name') unless @options[:exclude].to_s.empty?
    warn_msg(services_down.map { |item| item['name'].to_s }.join(', ') << ' not running') if services_down.any?
    ok_msg('All services running')
  end

  ###--- SUBSCRIPTION CHECK ---###
  def subscription
    return unless @options[:mode] == 'subscription'
    http_connect(path: "api2/json/nodes/#{@options[:node]}/subscription")
    data = JSON.parse(@response.body)['data']
    due_date = data['nextduedate']
    check_single_data(data: data['status'] == 'Inactive', message: 'Subscription not valid')
    check_multiple_data(
      data: Date.parse(due_date) < Date.today + @options[:warning].to_i,
      warn_msg: "Subscription will end at #{due_date}",
      ok_msg: "Subscription is valid till #{due_date}"
    )
  end

  ###--- NODE CHECKS ---###
  def format_float(float_data:)
    format("%.2f", float_data * 100).to_f.round # rubocop:disable  Style/StringLiterals, Style/FormatStringToken
  end

  # helper for percentage values
  def node_helper_to_pct(path: 'status', value:, output_msg:, perf_label: 'Usage', **args)
    http_connect(path: "api2/json/nodes/#{@options[:node]}/#{path}")
    data = JSON.parse(@response.body)['data']
    # calc used data
    value = if args.empty?
              format_float(float_data: data[value])
            else
              format_float(float_data: data[value].to_f / data[args[:value_to_compare]])
            end
    build_output(msg: "#{output_msg}: #{value}%")
    build_perfdata(perfdata: "#{perf_label}=#{value}%")
    check_thresholds(data: value)
  end

  # helper for unit values
  def node_helper_to_units(path: 'status', type:, value: 'used', output_msg:, unit: 'gb', perf_label: 'Usage')
    http_connect(path: "api2/json/nodes/#{@options[:node]}/#{path}")
    data = JSON.parse(@response.body)['data'][type][value]
    convert_bytes_to_unit(data: data, unit: unit)
    build_output(msg: "#{output_msg}: #{@usage}#{unit.upcase}")
    build_perfdata(perfdata: "#{perf_label}=#{@usage}#{unit.upcase}")
    check_thresholds(data: @usage)
  end

  # helper for rrddata
  def check_rrddata_path
    @options[:vmid] ? @rrddata_path = "#{@options[:node]}/#{@options[:type]}/#{@options[:vmid]}" : @rrddata_path = @options[:node]
  end

  def rrddata_helper(unit: 'kb', value:, output_msg:, perf_label: 'Usage')
    check_rrddata_path
    http_connect(path: "api2/json/nodes/#{@rrddata_path}/rrddata?timeframe=#{@options[:timeframe]}&cf=#{@options[:cf].upcase}")
    data = JSON.parse(@response.body)['data'][-1][value]
    unit == '%' ? @usage = format_float(float_data: data) : @usage = convert_bytes_to_unit(data: data, unit: unit)
    build_output(msg: "#{output_msg}: #{@usage}#{unit.upcase}")
    build_perfdata(perfdata: "#{perf_label}=#{@usage}#{unit.upcase}")
    check_thresholds(data: @usage)
  end

  ### node: cpu
  def cpu
    return unless @options[:mode] == 'cpu'
    node_helper_to_pct(value: 'cpu', output_msg: 'CPU usage')
  end

  ### node: io wait
  def io_wait
    return unless @options[:mode] == 'io_wait'
    node_helper_to_pct(value: 'wait', output_msg: 'IO Wait', perf_label: 'Wait')
  end

  ### node: memory
  def mem
    return unless @options[:mode] == 'memory'
    node_helper_to_units(type: 'memory', output_msg: 'Memory Usage')
  end

  ### node: ksm
  def ksm
    return unless @options[:mode] == 'ksm'
    node_helper_to_units(type: 'ksm', value: 'shared', unit: 'mb', output_msg: 'KSM sharing')
  end

  ### node: storage
  def storage
    return unless @options[:mode] == 'storage'
    node_helper_to_pct(
      path: "storage/#{@options[:name]}/status",
      value: 'used',
      value_to_compare: 'total',
      output_msg: 'Storage usage'
    )
  end

  ### node: netin
  def net_in
    return unless @options[:mode] == 'net_in'
    rrddata_helper(value: 'netin', output_msg: 'Network usage in')
  end

  ### node: netout
  def net_out
    return unless @options[:mode] == 'net_out'
    rrddata_helper(value: 'netout', output_msg: 'Network usage out')
  end

  ###--- QEMU, LXC CHECKS ---###
  # disk
  def vm_disk_write
    return unless @options[:mode] == 'vm_disk_write'
    rrddata_helper(value: 'diskwrite', output_msg: 'Disk write')
  end

  def vm_disk_read
    return unless @options[:mode] == 'vm_disk_read'
    rrddata_helper(value: 'diskread', output_msg: 'Disk read')
  end

  # cpu
  def vm_cpu
    return unless @options[:mode] == 'vm_cpu'
    rrddata_helper(unit: '%', value: 'cpu', output_msg: 'CPU usage')
  end

  # network
  def vm_net_in
    return unless @options[:mode] == 'vm_net_in'
    rrddata_helper(value: 'netin', output_msg: 'Network usage in')
  end

  def vm_net_out
    return unless @options[:mode] == 'vm_net_out'
    rrddata_helper(value: 'netout', output_msg: 'Network usage out')
  end
end

CheckPve.new(options)
