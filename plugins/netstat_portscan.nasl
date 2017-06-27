#TRUSTED 8fbd395949f55df40f15813200bf8d85a3330667f851cf4bf87fc35e0f9a8d90744ff48a2915e8a1f2c5e3e4d6b33cc9b9b4120bdfadc10160b1fdbc4e7a01a09a1c8589c647f84fa9cf67ce909edbe3d138890ae5e69b50427f0e44b9f6ca2644c9e9e7482c154751253547548db93f58b2ced40a74ed781bc47f69d0cabaa0f7bfa8c0e00a5b893a7a99f3f4f7ea4c9a9330a0c8e157bf901c5caeec87156e7142905735bc1a24288adc74904564fc2a2393e335ea8814123b2fd261ee70c9a2da59d86d564a15ca3117c2c4df0fa69f78a4fc0a4a195aa67e913994ec18142dd99ab71eb971fb5fd7a56801f3fa00beb3d6ef50d83249a2f404440eb557a06dc63c574b91ea5dcef73261584062ee8f2b8a69326a13c07e34b81caabb87e07b58d7656ec650e35aad77f7b3c6bb09baa1b0949eab4b658181d2f9565b7b9df93999b4e30aca41615f85fb94ec59ac981414e8d3c9686eb580ce60e94984b67d587e0c08c1b1f2e8b3b17f5d6ac8cb756b626de69854a844ea9d6a85986ea766b6156795c64d176648f0bf0634a127db2fea4b50d3c5e21d58b1e4ec57ed7f35ef169572c00d369496ac5dc95086329c37172ac568e97e7aea5bdc6f362c9d29b7afd3be0439d7c75782b731b514fbaacd01590c67ada993783881e3a37d544d9a3b3ba83ad25bf30828a655f11fa019f184ebc44ac63defb5b2faa8698099
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(14272);
  script_version("1.65");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/02/21");

  script_name(english:"netstat portscanner (SSH)");
  script_summary(english:"Find open ports with netstat.");

  script_set_attribute(attribute:'synopsis', value:
"Remote open ports are enumerated via SSH.");
  script_set_attribute(attribute:'description', value:
"This plugin runs 'netstat' on the remote machine to enumerate open
ports.

See the section 'plugins options' about configuring this plugin.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Netstat");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_SCANNER);
  script_family(english:"Port scanners");

  script_copyright(english:"This script is Copyright (C) 2004-2017 Tenable Network Security, Inc.");

  script_dependencies("ping_host.nasl", "ssh_settings.nasl", "portscanners_settings.nasl");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ports.inc");
include("ssh_func.inc");
include("agent.inc");

if ( get_kb_item("PortscannersSettings/run_only_if_needed") &&
     get_kb_item("Host/full_scan") )
  exit(0, "The remote host has already been port-scanned.");

# If plugin debugging is enabled, enable packet logging
if(get_kb_item("global_settings/enable_plugin_debugging"))
  SSH_LOG_PACKETS = TRUE;

buf = "";
ssh_banner = "";
n_tcp = 0; n_udp = 0;

# On the local machine, just run the command
if (islocalhost())
{
  if ( ! defined_func("pread") ) exit(1, "The NASL 'pread()' function is not defined.");
  buf = pread(cmd: "netstat", argv: make_list("netstat", "-a", "-n"));
  if ( buf )
  {
    set_kb_item(name:"Host/netstat", value:buf);
    set_kb_item(name:"Host/netstat/method", value:"local");
    if (agent())
    {
      agent_ip = agent_get_ip();
      if(!isnull(agent_ip))
        report_xml_tag(tag:"host-ip", value:agent_ip);
    }
  }
  else exit(1, "Failed to run the command 'netstat -a -n' on localhost.");
}
else if ( get_kb_item("Secret/SSH/login") )
{
  port22 = kb_ssh_transport();
  if ( port22 && get_port_state(port22) )
  {
    soc = open_sock_tcp(port22);
    if ( soc )
    {
      ssh_banner = recv_line(socket:soc, length:1024);

      if (ssh_banner == "" || isnull(ssh_banner))
        ssh_banner = recv_line(socket:soc, length:1024, timeout:10);

      close(soc);
      if (
         "-cisco-" >< tolower(ssh_banner) ||
         "-cisco_" >< tolower(ssh_banner)
      ) exit(0, 'The netstat portscanner doesn\'t run against Cisco devices.');
    }
  }

  # Need to set try none for Sonicwall
  set_kb_item(name:"/tmp/ssh/try_none", value:TRUE);
  timeout = get_ssh_read_timeout();
  if (timeout <= 5) set_ssh_read_timeout(10);

  if ("force10networks.com" >< ssh_banner) sleep(1);

  ret = ssh_open_connection();

  # nb: Sonicwall needs a delay between the initial banner grab
  #     and  calling 'ssh_open_connection()'.
  if (
    !ret &&
    "please try again" >< get_ssh_error()
  )
  {
    for (i=0; i<5 && !ret; i++)
    {
      # We need to unset login failure if we are going to try again
      if(get_kb_item("SSH/login/failed")) rm_kb_item(name:"SSH/login/failed");
      sleep(i*2);
      ret = ssh_open_connection();
    }
  }

  if (! ret )
  {
    error_msg = get_ssh_error();
    if (isnull(error_msg)) error_msg = "Failed to open an SSH connection.";

    exit(1, error_msg);
  }

  buf = ssh_cmd(cmd:"cmd /c netstat -an", timeout:60);
  if('Command Line Interface is starting up, please wait' >< buf)
  {
    ssh_close_connection();
    exit(0, 'The netstat portscanner doesn\'t run against Cisco devices.');
  }

  if ("LISTENING" >!< buf && "0.0.0.0:0" >!< buf && "*.*" >!< buf)
  {
    # Brocade
    if (
      !buf &&
      'rbash: sh: command not found' >< ssh_cmd_error()
    )
    {
      cmd = "netstat -an";
      buf = ssh_cmd(cmd:cmd, nosh:TRUE, timeout:60);
    }
    # NetApp Data ONTAP
    else if (
      !buf &&
      "cmd not found.  Type '?' for a list of commands" >< ssh_cmd_error()
    )
    {
      ssh_close_connection();
      sock_g = ssh_open_connection();
      if (!sock_g) exit(1, "Failed to reopen an SSH connection.");
      sleep(1);

      cmd = "netstat -an";
      buf = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, noexec:TRUE, timeout:60);
    }
    #NetApp Data ONTAP clustered
    else if (
      !buf &&
      "Error: Ambiguous command" >< ssh_cmd_error() ||
      "is not a recognized command" >< ssh_cmd_error()
    )
    {
      ssh_close_connection();
      sock_g = ssh_open_connection();
      if (!sock_g) exit(1, "Failed to reopen an SSH connection.");
      sleep(1);

      cmd = "system node run -node local netstat -an";
      buf = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, noexec:TRUE, timeout:60);
    }

    # ScreenOS
    else if (
      !buf &&
      "-NetScreen" >< ssh_banner
    )
    {
      ssh_close_connection();
      sock_g = ssh_open_connection();
      if (!sock_g) exit(1, "Failed to reopen an SSH connection.");
      sleep(1);

      cmd = "get socket";
      buf = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, noexec:TRUE, timeout:60);
    }
    else
    {
      buf = ssh_cmd(cmd:"netstat -a -n", timeout:60);
    }

    if (
      !buf ||
      "Cmd exec error" >< buf ||
      "Cmd parse error" >< buf ||
      "command parse error before" >< buf ||
      "(Press 'a' to accept):" >< buf ||
      "Syntax error while parsing " >< buf
    ) { ssh_close_connection(); exit(1, "The 'netstat' command failed to be executed."); }
  }
  ssh_close_connection();
  set_kb_item(name:"Host/netstat", value:buf);
  set_kb_item(name:"Host/netstat/method", value:"ssh");
}
else exit(0, "No credentials are available to login to the host.");

ip = get_host_ip();
lines = split(buf);
n = max_index(lines);
if (n == 0) n = 1; i = 0;
scanner_status(current: 0, total: n);
scanned = 0;

check = get_kb_item("PortscannersSettings/probe_TCP_ports");


if ("yes" >< get_preference("unscanned_closed"))
  unscanned_closed = TRUE;
else
  unscanned_closed = FALSE;

if (unscanned_closed)
{
  tested_tcp_ports = get_tested_ports(proto: 'tcp');
  tested_udp_ports = get_tested_ports(proto: 'udp');
}
else
{
  tested_tcp_ports = make_list();
  tested_udp_ports = make_list();
}

discovered_tcp_ports = make_array();
discovered_udp_ports = make_array();

# to help make the regex a little bit cleaner
ipv4addr = '[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+';
ipv6addr = '[a-f0-9:]+(?:%[0-9a-z]+)?';
unspec_ipv4 = '0\\.0\\.0\\.0';
unspec_ipv6 = ':+(?:%[0-9a-z]+)?';

# supports IPv4, IPv6, IPv6 zone ids
win_regex = win_regex = '^[ \t]*(TCP|UDP)[ \t]+(?|(' +ipv4addr+ ')|\\[(' +ipv6addr+ ')\\]|(\\*)):([0-9]+)[ \t]+(?|(' +unspec_ipv4+ ')|(\\[?' +unspec_ipv6+ '\\]?)|(\\*)):(?:[0-9]+|\\*)(?:[ \t]+LISTENING)?';

# unix regex supports ipv6/ipv4 embedded address
# tcp 0 0 ::ffff:192.168.1.3:7001 :::* LISTEN (ipv6/ipv4 embedded address)
nix_regex = '^(tcp|udp)4?6?[ \t].*[ \t]+(?|(?:::ffff[:.])?(' +ipv4addr+ ')|(' +ipv6addr+ ')|(\\*))[:.]([0-9]+)[ \t]+(?|(' +unspec_ipv4+ ')|(' +unspec_ipv6+ ')|(\\*))[:.](?:[0-9]+|\\*)(?:[ \t]+LISTEN)?';

foreach line (lines)
{
  line = chomp(line);
  # Windows
  v = eregmatch(pattern: win_regex, string: line, icase: 0);

  # Unix
  if (isnull(v))
    v = eregmatch(pattern: nix_regex, string: line, icase: 1);

  # Solaris 9 / NetApp
  if (isnull(v))
  {
    if (last_seen_proto)
    {
      if (last_seen_proto == 'udp')
      {
        v = eregmatch(pattern: '^[ \t]*(\\*|[0-9.]+)\\.([0-9]+)[ \t]+Idle', string: line);
        if (isnull(v)) v = eregmatch(pattern: '^[ \t]*(\\*|[0-9.]+)\\.([0-9]+)[ \t]+(\\*\\.\\*|[0-9.]+)[ \t]+[0-9]+[ \t]+[0-9]+$', string: line);
      }
      else
        v = eregmatch(pattern: '^[ \t]*(\\*|[0-9.]+)\\.([0-9]+)[ \t]+\\*\\.\\*[ \t]+.*(Idle|LISTEN)', string: line);

      if (! isnull(v))
      {
        # "Fix" array
        v[3] = v[2]; v[2] = v[1]; v[1] = last_seen_proto;
      }
    }
    if (isnull(v))
    {
      v = eregmatch(pattern: '^(TCP|UDP)(: +IPv4)?[ \t\r\n]*$', string: line);
      if (isnull(v)) v = eregmatch(pattern: '^Active (TCP|UDP) (connections|sockets) \\(including servers\\)[ \t\r\n]*$', string: line);
      if (!isnull(v))
      {
        last_seen_proto = tolower(v[1]);
        v = NULL;
      }
    }
  }

  # ScreenOS
  # Socket  Type   State      Remote IP         Port    Local IP         Port
  #    1  tcp4/6  listen     ::                   0    ::                443
  #    2  tcp4/6  listen     ::                   0    ::                 23
  #    3  tcp4/6  listen     ::                   0    ::                 22
  #   67  udp4/6  open       ::                   0    ::                500
  if (isnull(v))
  {
    v = eregmatch(pattern:'^[ \t]*[0-9]+[ \t]+(tcp|udp)4/6[ \t]+(listen|open)[ \t]+([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+|::)[ \t]+[0-9]+[ \t]+([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+|::)[ \t]+([0-9]+)[ \t]*', string:line, icase:TRUE);
    if (!isnull(v))
    {
      proto = v[1];
      state = v[2];
      local_ip = v[4];
      local_port = v[5];

      # "Fix" array
      v[1] = proto;
      v[2] = local_ip;
      v[3] = local_port;
    }
  }

  if (!isnull(v))
  {
    proto = tolower(v[1]);
    addr = v[2];
    port = int(v[3]);
    checktcp = (check && proto == "tcp");

    if (port < 1 || port > 65535)
    {
      spad_log(message:string('netstat_portscan(', get_host_ip(), '): invalid port number ', port, '\n'));
    }

    # no loopback addresses, unless target is localhost
    addr_parts = split(addr, sep:".");
    if ((addr_parts[0] == "127." || addr == "::1") && addr != ip)
      continue;

    if (unscanned_closed)
      if (
        (proto == "tcp" && ! tested_tcp_ports[port]) ||
        (proto == "udp" && ! tested_udp_ports[port])
      ) continue;

    if (
      (proto == "tcp" && discovered_tcp_ports[port]) ||
      (proto == "udp" && discovered_udp_ports[port])
    ) continue;

    if (checktcp)
    {
      soc = open_sock_tcp(port);
      if (soc)
      {
        scanner_add_port(proto: proto, port: port);
        close(soc);
      }
    }
    else
    {
      scanner_add_port(proto: proto, port: port);
    }

    if (proto == "tcp")
    {
      n_tcp ++;
      discovered_tcp_ports[port]++;
    }
    else if (proto == "udp")
    {
      n_udp ++;
      discovered_udp_ports[port]++;
    }
    scanned ++;
  }
  scanner_status(current: i++, total: n);
}

if (scanned)
{
  set_kb_item(name: "Host/scanned", value: TRUE);
  set_kb_item(name: "Host/udp_scanned", value: TRUE);
  set_kb_item(name: "Host/full_scan", value: TRUE);

  set_kb_item(name:"NetstatScanner/TCP/OpenPortsNb", value: n_tcp);
  set_kb_item(name:"NetstatScanner/UDP/OpenPortsNb", value: n_udp);

  set_kb_item(name: "Host/TCP/scanned", value: TRUE);
  set_kb_item(name: "Host/UDP/scanned", value: TRUE);
  set_kb_item(name: "Host/TCP/full_scan", value: TRUE);
  set_kb_item(name: "Host/UDP/full_scan", value: TRUE);

  set_kb_item(name: 'Host/scanners/netstat', value: TRUE);
}

scanner_status(current: n, total: n);
