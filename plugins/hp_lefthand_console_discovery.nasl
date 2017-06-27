#TRUSTED 1f71dadd5e9bb74b77b597c3d8afe0b351dbfb5d00afa677049fc9622089c42b75455f88c2beaf9380b2c64633654232bc34dfc16049f5a01020fe9f7b8bf3bece27d2610ea02928897d26cbe9b5d67d9e2c3b9c428d6473072bd5b065824297bd10988a2830e6d06c8cdc58b89a432a6ca4dc92016c125ba005f0c88734d9d046d01426c9446b85900c5711bcea79f6662b06d7b05fca5e8453d5f28bab2c72570fb767359a9161bc0191073465955e42c4e3a23b904bb1358edfcbce57a62aff1bd2e317771da86d615aa31ebe6e95c78178cb06cfd68423f861a1060e1aacef48b893ec689fb067e8a8e03d4363a32238b54b4fd76b59f94d81ff4e479add36d13c976ab4e63ef0a816295838a35a59ed25a76b322db17686f76a043bcc74f2bd5ede4d7d68213abc31c4ffb829a29ddd8351b9119e588981d69191724a2a725075edc80cc4c9fc1f40612e16be80d396721902e7820b1f79fe88ea9fcdb501cd13435b763e73231c7c19c35a2488a0fdcc60d95c6527638d51b9c56e244491ef09669cee7e20266c76cd2bfa5764482a452baf72f14930ee59c59ea4d2a36f60680c34693c7525e44b9a73e5b76c836bf7282b6d1e7274cc4ac4b4ff95574c2cff2c0456be63ffcb4d66c88cf3935a7e37eab3d66495e851ec16389a3b3c17892d0022ae9bb2a61f2643312a331a8d2b6a41c8c1b05258b8923f5b21e2d4
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("recvfrom")) exit(1, "recvfrom() not defined.");

include("compat.inc");

if (description)
{
  script_id(64631);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/04/10");

  script_name(english:"HP LeftHand OS Console Discovery Detection");
  script_summary(english:"Attempts to get info from the service");

  script_set_attribute(attribute:"synopsis", value:"A discovery service is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"The HP LeftHand OS (formerly SAN/iQ) console discovery service, used
by systems such as the HP Virtual SAN Appliance, is running on the
remote host. This service allows management applications to discover
storage nodes.");
  script_set_attribute(attribute:"see_also", value:"http://h10032.www1.hp.com/ctg/Manual/c01750064.pdf");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:san/iq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 27491);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

if ( TARGET_IS_IPV6 ) exit(1, "IPv6 is not supported");

function check_results(data, port, udp)
{
  local_var fields, report, group;
  if (isnull(data))
    return FALSE;

  fields = split(data, sep:'\x00', keep:FALSE);
  if (fields[0] != 'NSMreply:ver0.01')
    return FALSE;

  report = '';

  if (fields[3] != '')
    report += '\n  MAC address : ' + fields[3];
  if (fields[5] != '')
    report += '\n  Hostname : ' + fields[5];
  if (fields[8] != '')
    report += '\n  RAID configuration : ' + fields[8];
  if (fields[9] != '')
  {
    if (udp)
      set_kb_item(name:'lefthand_os/udp/' + port + '/version', value:fields[9]);
    else
      set_kb_item(name:'lefthand_os/' + port + '/version', value:fields[9]);
    report += '\n  Software version : ' + fields[9];
  }
  if (fields[11] != '')
  {
    group = fields[11];
    if (group == 'NO_SYSTEM_ID')
      group = 'none';
    report += '\n  Management group : ' + group;
  }
  if (fields[13] != '')
    report += '\n  Model : ' + fields[13];

  # the plugin can always expect to get some kind of results.
  # if there were no results, it's possible this is some other protocol
  if (report == '')
    return FALSE;

  if (udp)
    register_service(port:port, proto:'saniq_console_discovery', ipproto:'udp');
  else
    register_service(port:port, proto:'saniq_console_discovery');

  replace_kb_item(name:"HP/LeftHandOS", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\nNessus was able to gather the following information :\n' +
      report + '\n';
    if (udp)
      security_note(port:port, extra:report, proto:'udp');
    else
      security_note(port:port, extra:report);
  }
  else
  {
    if (udp)
      security_note(port:port, proto:'udp');
    else
      security_note(port:port);
  }

  return TRUE;
}

# first check UDP 27491
port = 27491;
soc = open_sock_udp(27491);
if (soc)
  soc2 = bind_sock_udp();

# don't know what this function does when it fails, but this seems like a reasonable check
if (!isnull(soc2) && soc2[0])
{
  recv_soc = soc2[0];
  sport = soc2[1];

  req =
    'NSMRequest:ver0.01\x00' +
    sport + '\x00' +
    '14\x00' +
    'UDP_DIRECT:' + get_host_ip() + '\x00';
  send(socket:soc, data:req);
  close(soc);

  res = recvfrom(socket:recv_soc, src:get_host_ip(), port:sport);
  close(recv_soc);
  udp_detected = check_results(data:res[0], port:port, udp:TRUE);
}

# then check TCP. the plugin forks at this point if thorough_tests is enabled
if (thorough_tests)
{
  port = get_unknown_svc(27491);
  if (!port) audit(AUDIT_SVC_KNOWN);
  if (!silent_service(port)) audit(AUDIT_FN_FAIL, 'silent_service', strcat('false for port ', port));
}
else port = 27491;
if (known_service(port:port)) exit(0, 'The service listening on port ' + port + ' has already been identified.');
if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (soc)
{
  req =
    'NSMRequest:ver0.01\x00' +
    '3449\x00' +
    '14\x00' +
    'TCP_DIRECT:' + get_host_ip() + '\x00';
  send(socket:soc, data:req);

  # the length isn't sent in the response, it's just a stream
  # of null delimited fields. 2k should be more than enough
  res = recv(socket:soc, length:2048);
  close(soc);
  tcp_detected = check_results(data:res, port:port);
}

if (!udp_detected && !tcp_detected)
  exit(0, 'The service was not detected on UDP 27491 or TCP ' + port + '.');
else if (!udp_detected)
  audit(AUDIT_NOT_DETECT, 'Console Discovery', strcat(port, ' (UDP)'));
else if (!tcp_detected)
  audit(AUDIT_NOT_DETECT, 'Console Discovery', port);
