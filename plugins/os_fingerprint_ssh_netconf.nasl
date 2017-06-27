#TRUSTED 12c984f5aef7562d23f3e713acf27867b6a5cda0da3a495a3bf4a6d2dd9c6b5cb884be173cb33c934993fa67496f651406d85e24962d118b912c29d58adfbca8c378b21b8895e10a61ebdccab861dc29f73695e81126fb818e4076294dc7479a0794fa3d3211d215eaf489aed710976834f7b3dd131b6ebd56199c713bb7e1aa29d17122abe1a8f2eadd8ae0b5b62e479f2cba43c382c695ebe08b51fa41fe8015dcc4b145d3764b7f495cfc6ee1130caee8ee17e19165345ea94b14e0cb56bf0f6655801e2e728740d06abfd32249544143f2486b3318f49ddf93ca1223238dc5860c20e4fb179022faa124dfba9906b233fbe638b022a92c41373dc639a7c4019f68c1e96b489dc2a1569906cc6368423199a3c48eddb5309731fb5c473e7d92dd92bba5dd7e050217f2c69a1b9cb90d5de586cec69944224e0d2b4b1c0e15467d00a1c2ec2da7f3a2e390e5461b387c45f736f53280c83f5dfe7ef74cd988063badf4e223d522cb7772e0e8c09dff74214c8f5f7a70f9b9543ecc38d1a66196d1a5c548ac83555ccb6d29b4f9296760b0c48d6d4ea7ed340081fa6641de56227c61293d9ced322eec8c36faee43417ddf51937ba3cea3f070a32dca4a19b7c90f6be6409749e9a6cdb6cc6ad19b188a4e5b0e8e7be91316cc9cc01f638a3bb2494c0e09ba8da563fbd1c228b538086a6931b305943b753be53fe801582949
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69181);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/11/17");

  script_name(english:"OS Identification : NETCONF Over SSH");
  script_summary(english:"Authenticates via SSH and looks for a netconf hello");

  script_set_attribute(attribute:"synopsis", value:
"It may be possible to fingerprint the remote host's operating system
by querying its management protocol."
  );
  script_set_attribute(attribute:"description", value:
"The remote host is using the NETCONF protocol over SSH.  The NETCONF
protocol is used to manage network devices.

It may be possible to determine the operating system name and version
by using the SSH credentials provided in the scan policy."
  );
  script_set_attribute(attribute:"see_also", value:"http://tools.ietf.org/html/rfc6241");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_settings.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include('audit.inc');
include('byte_func.inc');
include('global_settings.inc');
include('misc_func.inc');
include('ssh_func.inc');

##
# Sends a netconf payload over an already-established SSH channel,
# wrapping it in a SSH_MSG_CHANNEL_DATA header
#
# @anonparam data netconf request
# @return whatever send_ssh_packet() returns (don't know if that functions returns anything)
##
function _netconf_send()
{
  local_var data, payload;
  data = _FCT_ANON_ARGS[0];
  payload =
    raw_int32(i:remote_channel) + # global from ssh_func.inc
    putstring(buffer:data);

  return send_ssh_packet(payload:payload, code:raw_int8(i:94));
}

##
# Receives a netconf payload, removing the SSH-related header
#
# @return netconf payload
##
function _netconf_recv()
{
  local_var res, payload;
  res = recv_ssh_packet();
  payload = substr(res, 9); # code, channel, and length ignored
  return payload;
}

port = kb_ssh_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

if ( port && get_port_state(port) )
{
  soc = open_sock_tcp(port);
  if ( soc )
  {
    ssh_banner = recv_line(socket:soc, length:1024);
    close(soc);
    if ( "-Cisco-" >< ssh_banner )
    {
      CISCO++;
      if ("-Cisco-2." >< ssh_banner) CISCO_IOS_XR++;
    }
  }
}

# nb: needed for Cisco Wireless LAN Controllers and Sonicwall.
if (!CISCO)
{
  set_kb_item(name:"/tmp/ssh/try_none", value:TRUE);
  timeout = get_ssh_read_timeout();
  if (timeout <= 5) set_ssh_read_timeout(10);
}

# nb: needed for Cisco IOS XR
if (CISCO_IOS_XR) sleep(1);

if ("force10networks.com" >< ssh_banner) sleep(1);

success = ssh_open_connection();

# nb: Sonicwall needs a delay between the initial banner grab
#     and  calling 'ssh_open_connection()'.
if (
  !success &&
  "please try again" >< get_ssh_error()
)
{
  for (i=0; i<5 && !success; i++)
  {
    # We need to unset login failure if we are going to try again
    if(get_kb_item("SSH/login/failed")) rm_kb_item(name:"SSH/login/failed");
    sleep(i*2);
    success = ssh_open_connection();
  }
}

if (!success)
{
  error = get_ssh_error();
  if (strlen(error) == 0)
    msg = 'SSH authentication failed on port ' + port + ': unknown error.';
  else
    msg = 'SSH authentication failed on port ' + port + ': ' + error;
  exit(1, msg);
}

ssh_protocol = get_kb_item("SSH/protocol");
if (!isnull(ssh_protocol) && ssh_protocol == 1) exit(0, "The SSH server listening on port "+port+" only supports version 1 of the SSH protocol.");


ret = ssh_open_channel();
if (ret != 0)
{
  ssh_close_connection();
  audit(AUDIT_LISTEN_NOT_VULN, 'SSH', port);
}

# SSH_MSG_CHANNEL_REQUEST
channel_req =
  raw_int32(i:remote_channel) +
  putstring(buffer:'subsystem') +
  raw_int8(i:1) +  # want reply
  putstring(buffer:'netconf');
send_ssh_packet(payload:channel_req, code:raw_int8(i:98));

# skip over any packets that we don't care about
res = recv_ssh_packet();
while((ord(res[0]) == 93) || (ord(res[0]) == 95) || (ord(res[0])  == 98))
{
  if (ord(res[0]) == 95)
  {
    payload = getstring(buffer:res, pos:9);
    _ssh_cmd_error += payload;
    val = update_window_size(size:strlen(payload));
    if (val != 0)
      break;
  }
  res = recv_ssh_packet();
}

if (ord(res[0]) == SSH2_MSG_CHANNEL_FAILURE)
{
  ssh_close_connection();
  audit(AUDIT_NOT_LISTEN, 'netconf', port);
}
else if (ord(res[0]) != SSH2_MSG_CHANNEL_SUCCESS) # expected response
{
  if (!bugged_sshd) ssh_close_channel();
  ssh_close_connection();
  audit(AUDIT_RESP_BAD, port, 'netconf subsystem request');
}

res = recv_ssh_packet();
while((ord(res[0]) == 93) || (ord(res[0]) == 95) || (ord(res[0])  == 98))
{
  if (ord(res[0]) == 95)
  {
    payload = getstring(buffer:res, pos:9);
    _ssh_cmd_error += payload;
    val = update_window_size(size:strlen(payload));
    if (val != 0)
      break;
  }
  res = recv_ssh_packet();
}

hello = substr(res, 9);
if (hello !~ '^<hello' || 'netconf' >!< hello)
{
  ssh_close_connection();
  audit(AUDIT_NOT_LISTEN, 'netconf', port);
}

set_kb_item(name:'Host/netconf/' + port + '/hello', value:hello);

# Juniper IVE SA & IVE IC
if (hello =~ '<capability>http://xml.juniper.net/dmi/ive-(sa|ic)')
{
  _netconf_send('<rpc message-id="1"><get-system-information /></rpc>');
  sys_info = _netconf_recv();
  _netconf_send('<rpc message-id="2"><close-session/></rpc>'); # cleanup, response ignored
  ssh_close_connection();

  if (sys_info !~ '<os-name>ive-(sa|ic)') # sanity check
    audit(AUDIT_RESP_BAD, port, 'get-system-information');

  os = 'Pulse Connect Secure (formerly Juniper IVE OS)';

  match = eregmatch(string:sys_info, pattern:'<os-version>([^<]+)</os-version>');
  if (isnull(match))
    audit(AUDIT_RESP_BAD, port, 'get-system-information');
  else
    version = match[1];

  match = eregmatch(string:sys_info, pattern:'<hardware-model>([^<]+)</hardware-model>');
  if (!isnull(match))
  {
    model = match[1];
    set_kb_item(name:'Host/netconf/' + port + '/model', value:model);
  }

  set_kb_item(name:'Host/netconf/' + port + '/os', value:'Juniper IVE OS');
  set_kb_item(name:'Host/Juniper/IVE OS/Version', value:version);
  set_kb_item(name:'Host/OS/netconf', value:'Juniper IVE OS ' + version);
  set_kb_item(name:'Host/OS/netconf/Confidence', value:100);
  set_kb_item(name:'Host/OS/netconf/Type', value:'embedded');

  if (report_verbosity > 0)
  {
    report =
      '\n  Operating system : ' + os +
      '\n  Version          : ' + version;
    if (!isnull(model))
      report += '\n  Model            : ' + model;
    report += '\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);
}
else
{
  ssh_close_connection();

  if (report_verbosity > 0)
  {
    report =
      '\n' + 'Nessus was able to access the NETCONF SSH subsystem but was' +
      '\n' + 'unable to identify the device based on its hello message :\n\n' +
      hello;
    security_note(port:0, extra:report);
  }
  else security_note(0);
}
