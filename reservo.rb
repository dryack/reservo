# reservo - perform action on user-defined sets of servers using SSH
# Copyright (C) 2020  David Ryack

#!/somewhere/ruby-2.6.6/bin/ruby
require 'rubygems'
require 'net/ssh'
require 'io/console'
require 'set'
require 'slop'
require 'open3'

# TODO: add lib/ and break out classes, etc
# TODO: check https://www.fabfile.org/ for interesting options
# TODO: https://www.linuxtechi.com/quick-tips-sudo-command-linux-systems/
# running sudo on ALL commands across the commandline without having to reissue `sudo` prefix commands over and over
# TODO: slicing, if hosts ALL end in numbers, permit automatic selection of either evens or odds
DEBUGGING = 0 # set to 0 to turn on debugging statements

PROGRAM_DESC = 'Run commands on defined pools of servers using SSH'
VALID_ENVS = %w(prod master integration stage core test hq bi)

# TODO: List object
=begin
class List

end
=end

class Target
  attr_reader :result
  attr_reader :error
  attr_reader :target

  def initialize(opts, tgt, pwd, cmd)
    @@username  = opts[:username]
    @password   = pwd
    @@quiet     = opts[:quiet]
    @@silent  = opts[:silent]
    @target     = tgt
    @@command   = cmd
  end

  def execute
    result = ""
    error = ""

    Net::SSH.start("#{@target}", @@username, :password => @password) do |ssh|
      channel = ssh.open_channel do |ch|
        ch.request_pty
        ch.exec(@@command) do |ch, success|
          #raise "couldn't execute command" unless success

          ch.on_data do |c, data|
            #pp data if DEBUGGING == 0
            if data =~ /^\[sudo\] password for .*:/
              channel.send_data "#{@password}\n"
            # support scp
            elsif data =~ /^.*'s password:/
              channel.send_data "#{@password}\n"
            else
              result << data
            end
          end

          ch.on_extended_data do |c, type, data|
            error << "error: " + data
          end

          ch.on_close { puts "#{@target} done." unless @@quiet}
        end
        @result = result
        @error = error
      end
      channel.wait
    end
  rescue Net::SSH::Disconnect => e
    error << "ERROR: #{e}\n"
  rescue SocketError
    error << "ERROR: #{@target} cannot be found.\n"
  rescue Net::SSH::ConnectionTimeout
    error << "ERROR: #{@target} timed out.\n"
  rescue Net::SSH::AuthenticationFailed
    error << "ERROR: could not authenticate #{@@username} on #{@target}"
  ensure
    @error = error
  end

end

def arg_parse
  opts = Slop.parse do |o|
    o.banner =  "usage: reservo [options] remote_command"
    o.bool      '--sudo', 'run commands using sudo on remote host'
    o.string    '-u', '--username', 'username to pass to ssh (default $USER)', default: ENV['USER']
    o.separator "Target definition options:"
    o.array     '--envs', "environment(s) [#{VALID_ENVS.join(', ')}]", delimiter: ','
    o.array     '--pools', "pool(s)", delimiter: ','
    o.array     '--hosts', 'manually specify hosts separated by commas', delimeter: ','
    o.array     '--hosts-file', 'specify file(s) listing host names', delimeter: ','
    o.array     '--exclude-hosts', 'specify hosts to avoid touching. in the event of a conflict, an exclusion will have the final word', delimeter: ','
    o.bool      '-E', '--empty-is-wildcard', 'if true, not specifying target ENVS will result in all ENVS being touched', default: false
    #TODO: chunks - allow the user to specify blocks of hosts to be touched, with no further operations to be done until those are done
    #TODO: delays - user able to specify a delay between Target executions
    o.separator "Ansible Pull Commands:"
    o.bool      '--ansoff', "Turn off ansible cron job for reason specified using the `--ansmsg' option"
    o.string    '--ansmsg', "Message placed in ansible-pull cron (default: 'shut off by $USER on $DATE')", default: "shut off by #{ENV['USER']} " + Time.new.to_s
    o.bool      '--anson', "Turn on ansible cron job and delete any comment left on past use of --ansoff"
    o.bool      '--ansstatus', "Check whether the ansible cron job is disabled or not, and prints any comments"
    o.bool      '--anslogact', "Has an ansible run happened over the last 2 days on target nodes?"
    o.separator "Misc:"
    o.int       '-t', '--max-threads', 'maximum number of threads to use (default: 10)', default: 10
    o.bool      '-D', '--discovery-mode', 'skips environment validation and disregards commands'
    #TODO: multiple levels of quiet, suppress `xxx done.` msgs, then results msgs, etc...
    #TODO: prompt mode -- automatically sets threads to 1, displays the result of a single host, and then prompts
    # whether you wish to continue processing
    o.bool      '-Q', '--quiet', 'suppress thread result reporting'
    o.bool      '-S', '--silent', 'suppress target results; errors will still be reported. this option is incompatible with --delimiter string'
    #o.string   '-d', '--delimiter-string', "define string that will separate target results default: #{DEFAULT_DELIMITER.inspect}", default: DEFAULT_DELIMITER
    #o.array    '--env-data-location', 'overrides the location of bconfigs/classes'
    o.bool      '--help' , 'display this help message'
  end
rescue Slop::UnknownOption => e
  puts e
  exit 2
end

def print_help(opts)
  puts "\n" + PROGRAM_DESC
  puts opts.to_s
  exit 0
end

def assemble_hosts_query(envs, pools, wildcard=false)
  if wildcard
    envs.empty? ? env_list = '.*' : env_list = envs.join('|')
    pools.empty? ? pool_list = '.*' : pool_list = pools.join('|')
  elsif !wildcard
    envs.empty? ? env_list = '' : env_list = envs.join('|')
    pools.empty? ? pool_list = '' : pool_list = pools.join('|')
  end
  #TODO: check for pcregrep and egrep, use `grep -E` if egrep command unavailable.
  # TODO: investigate alternatives to pcregrep in case it's unavailable
  grep_cmd_1 = "pcregrep -ir \"#{pool_list}\" . "
  grep_cmd_2 = "egrep -i \"\\-#{env_list}\\-\""
  for_cmd = "for S in $(#{grep_cmd_1} | tr -d '/' | awk -F'.' '{print $2}' | sort -u);"
  do_cmd = "do ls -1 ../nodes/slc/slc-*-$S* | awk -F'/' '{print $4}' | awk -F '.' '{print  $1}' | #{grep_cmd_2} | grep -v wordpress; done 2> /dev/null"
  final_cmd_string = "#{for_cmd}#{do_cmd}"
end

def remove_exclusions(list, exclusions)
  list.delete_if {|x| exclusions.include? x}
  list
end

def make_hosts_list(hosts, envs, pools, files, options)
  list = Set.new
  grep_res = []

  unless files.empty?
    files.each do |f|
      File.open(f).each do |line|
        list << line.chomp
      end
    end
  end

  Dir.chdir("#{Dir.home}/projects/bconfigs/classes") do
    # puts Dir.pwd # debug
    wildcard = options[:empty_is_wildcard]
    grep_res = `#{assemble_hosts_query(envs, pools, wildcard)}`
  end
  grep_res.split("\n").each do |x|
    list << x.chomp
  end
  hosts.each do |x|
    list << x.chomp
  end

  remove_exclusions(list, options[:exclude_hosts])
rescue Errno::ENOENT => e
  puts e
  exit 1
end

def pluralize(num, singular, plural=nil)
  if num == 1
    "#{singular}"
  elsif plural
    "#{plural}"
  else
    "#{singular}"
  end
end

def validate_envs(opts)
  unless opts[:discovery_mode]
    # if the intersection of VALID_ENVS and opts[:envs] equals opts[:envs], we know there are no invalid ENVS
    unless (VALID_ENVS.sort & opts[:envs].sort) == opts[:envs].sort || opts[:envs].empty?
      bad_envs = opts[:envs] - VALID_ENVS
      puts "'#{bad_envs.join(', ')}' #{pluralize(bad_envs.size,"is", "are")} not #{pluralize(bad_envs.size,"a known environment", "known environments")}."
      exit 1
    end
  end
  opts[:envs]
end

# necessary cludge due to limitations in slop
def chk_mutually_excl_opts
  if ARGV.include? "--anson"
    if ARGV.include?("--ansoff") || ARGV.include?("--ansstatus")
      puts "Options --anson cannot be used with --ansoff or --ansstatus."
      exit 1
    end
  end
  if ARGV.include? "--ansstatus"
    if ARGV.include?("--anson") || ARGV.include?("--ansoff")
      puts "Option --anson cannot be used with --ansoff or --anson."
      exit 1
    end
  end
  if ARGV.include? "--ansoff"
    if ARGV.include?("--anson") || ARGV.include?("--ansstatus")
      puts "Option --anson cannot be used with --anson or --anstatus"
      exit 1
    end
  end
end

def ansible_off(options, file)
  msg = options[:ansmsg]
  debug_command = ";cat #{file}"
  command =  'sudo grep -q -e \'^\*\/30.*1500$\' ' + file + ' && sudo sed -i \'/^\*\/30.*1500$/s/^/#/\' ' + file +
      ' && sudo sed -i \'/^#\*\/30.*1500$/i # ' + msg + "' #{file}" +
      "#{debug_command if DEBUGGING == 0}"
  pp msg if DEBUGGING == 0
  pp command if DEBUGGING == 0
  #exit 17
  command
end

def ansible_on(file)
  debug_command = ";cat #{file}"
  testcmd = 'sudo grep -q -e \'^#\*\/30.*1500$\' ' + file # testing that ansible is actually commented out
  or_cmd = ' || echo Ansible pull cron already active.'
  and_cmd = ' && sudo tac ' + file + ' | sed -r -e \'/^#\*\/30.*$/{n;d}\' | sed -r -e \'/^#\*\/30.*$/{s/^#//}\' | sudo tac > ~/ansible-pull.tmp && sudo mv ~/ansible-pull.tmp ' + file
  command = testcmd + and_cmd + or_cmd + "#{debug_command if DEBUGGING == 0}"
  pp command if DEBUGGING == 0
  command
end

def ansible_status_chk(file)
  debug_command = ";cat #{file}"
  testcmd = 'sudo grep -q -e \'^#\*\/30.*1500$\' ' + file # testing that ansible is actually commented out
  or_cmd = ' || echo Ansible pull cron job is active.'
  and_cmd = ' && echo Ansible pull cron job is inactive: $(grep -e "^# " /etc/cron.d/ansible-pull | grep -v -e "^#\*" -e "^# ansible-pull")'
  command = testcmd + and_cmd + or_cmd + "#{debug_command if DEBUGGING == 0}"
end

def ansible_last_pull(file)
  #TODO: create custom slop option type that has a default value, but ONLY when it has been specified on the command
  # line
  command = "sudo find /var/log -type f -name #{file} -mtime +2"
end

def build_job(list, command, options)
  print "password? "
  password = STDIN.noecho(&:gets).chomp
  puts
  batch = []
  msg = ""
  ansible_pull_file = "/etc/cron.d/ansible-pull"
  ansible_log_file = "ansible.last.log"
  # we stop these from being severally triggered at chk_mutually_excl_opts
  command = ansible_off(options, ansible_pull_file) if options[:ansoff]
  command = ansible_on(ansible_pull_file) if options[:anson]
  command = ansible_status_chk(ansible_pull_file) if options[:ansstatus]
  command = ansible_last_pull(ansible_log_file) if options [:anslogact]

  list.each do |node|
    batch << Target.new(options, node, password, command)
  end
  batch
end

def run_job(batch, options)
  jobs = Queue.new

  batch.sort_by!(&:target).each do |job|
    jobs.push job
  end

  workers = (POOL_SIZE).times.map do
    Thread.new do
      begin
        while x = jobs.pop(true)
          x.execute
        end
      rescue ThreadError
      rescue Net::SSH::Exception => e
        puts "#{e}:  #{x.target}"
      end
    end
  end

  workers.map(&:join)

  batch.each do |result|
    puts "\n#{result.target}:\n" unless options[:silent]
    unless result.error.empty?
      puts result.error
    end
    puts result.result unless options[:silent]
  end
end

begin
  argv = ARGV # we need to preserve the pre-slop args for processing
  chk_mutually_excl_opts
  #node = ""
  #DEFAULT_DELIMITER = "\n#{node}\n----------------"
  options = {}
  list = Set.new
  opts = arg_parse
  options = opts.to_hash
  POOL_SIZE = options[:max_threads]

  print_help(opts) if ARGV.empty? || options[:help]

  command = opts.arguments.join(' ')
  command.insert(0, 'sudo ') if options[:sudo]

  pp options if DEBUGGING == 0
  pp command if DEBUGGING == 0
  pp ENV['SSH_AUTH_SOCK'] if DEBUGGING == 0

  hosts = options[:hosts]
  envs = validate_envs(options)
  pools = options[:pools]
  files = options[:hosts_file]
  list = make_hosts_list(hosts, envs, pools, files, options)
  if list.size == 0
    puts "No hosts to be touched. Exiting."
    exit 1
  end
  puts "touching #{list.size} hosts#{":  " + list.to_a.join(', ') if DEBUGGING == 0}"

  start_t = Time.now.to_f
  batch = build_job(list, command, options)
  run_job(batch, options)
  end_t = Time.now.to_f
  puts "\nTouched #{batch.size} nodes in #{(end_t - start_t).round(2)} secs" unless options[:silent]
end

