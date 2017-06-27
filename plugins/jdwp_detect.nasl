#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58400);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"Java Debug Wire Protocol Detection");
  script_summary(english:"Sends the 'version' command to the JDWP daemon");

  script_set_attribute(
    attribute:"synopsis",
    value:"A debugger service is running on the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A Java Debug Wire Protocol (JDWP) server was detected on the remote
host.  This is a network protocol that allows debugging of a remote
Java virtual machine.  Authentication is not required to access this
service.  A remote, unauthenticated attacker could connect to this
service and execute arbitrary Java code.

Depending on the application being debugged, it is possible that this
service will stop running after it has been detected by Nessus. As such, 
this plugin only runs if 'Safe checks' have been disabled."
  );
  script_set_attribute(attribute:"see_also", value:"http://docs.oracle.com/javase/1.4.2/docs/guide/jpda/");
  script_set_attribute(attribute:"see_also", value:"http://docs.oracle.com/javase/1.4.2/docs/guide/jpda/jdwp-spec.html");
  script_set_attribute(
    attribute:"solution",
    value:"Filter incoming traffic to this port or disable this service."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/20");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown");
  script_require_keys("Settings/ThoroughTests");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");

global_var JDWP_CMDSET_VM, JDWP_VM_VERSION, FLAGS_REPLY_PACKET;
JDWP_CMDSET_VM = 1;
JDWP_VM_VERSION = 1;
JDWP_VM_DISPOSE = 6;
FLAGS_REPLY_PACKET = 0x80; # this is the only bit defined for the flags field

global_var pkt_id, port;
pkt_id = 0;

##
# Sends a JDWP packet and receives the corresponding reply
#
# @param socket TCP socket to write request to
# @param cmd_set the command set to use (int)
# @param cmd the command to run (int)
# @param data command data (optional)
# @remark this function exits if any protocol errors are encountered
#
# @return 'data' field from the JDWP reply packet
##
function jdwp_send_recv(socket, cmd_set, cmd, data)
{
  send_cmd(socket:socket, cmd_set:cmd_set, cmd:cmd, data:data);
  return recv_reply(socket);
}

##
# Sends a JDWP packet
#
# @param socket TCP socket to write request to
# @param cmd_set the command set to use (int)
# @param cmd the command to run (int)
# @param data command data (optional)
#
# @return number of bytes written to 'socket'
##
function send_cmd(socket, cmd_set, cmd, data)
{
  local_var pkt;

  pkt_id++;
  pkt =
    mkdword(pkt_id) + # id
    mkbyte(0x00) +    # flags (not used for command packets)
    mkbyte(cmd_set) + # command set
    mkbyte(cmd) +     # command
    data;             # variable
  pkt = mkdword(strlen(pkt) + 4) + pkt;  # the length field itself is included in the length of the packet
  
  return send(socket:socket, data:pkt);
}

##
# Receives and processes a JDWP reply packet
#
# @anonparam socket TCP socket to read reply from
# @remark this function exits if any protocol errors are encountered
#
# @return 'data' field from the JDWP reply packet
##
function recv_reply()
{
  local_var socket, length, pkt, id, flags, error_code, data;
  socket = _FCT_ANON_ARGS[0];

  length = recv(socket:socket, length:4);
  if (strlen(length) != 4)
  {
    close(socket);
    exit(1, 'Length not received on port ' + port);
  }

  length = getdword(blob:length, pos:0) - 4;

  #
  # Do not process responses bigger than 10Mb
  #
  if (length >= 10*1024*1024) 
    exit(1, 'Packet length advertised on port ' + port + ' is too big.');

  pkt = recv(socket:socket, length:length);
  if (strlen(pkt) != length)
  {
    close(socket);
    exit(1, 'Malformed response received on port ' + port);
  }
 
  id = getdword(blob:pkt, pos:0);
  if (id != pkt_id)
  {
    # ignore out of sequence packets. this usually happens as soon as the debugger
    # is started. request ID 1 is sent, and reply 0 is sent before reply 1
    if (id < pkt_id)
      return recv_reply(socket);

    close(socket);
    exit(1, 'Unexpected id received on port ' + port + ' (seen: ' + id + ', expected: ' + pkt_id + ').');
  }
 
  flags = getbyte(blob:pkt, pos:4);
  if (!(flags & FLAGS_REPLY_PACKET))
  {
    close(socket);
    exit(1, 'Unexpected flags received on port ' + port + ': ' + flags);
  }
 
  error_code = getword(blob:pkt, pos:5);
  if (error_code != 0)
  {
    close(socket);
    exit(1, 'Unexpected error code received on port ' + port + ': ' + error_code);
  }

  data = substr(pkt, 7);
  return data;
}

##
# Parses the fields from VirtualMachine / Version reply data
#
# @anonparam reply Version command reply data
# @remark this function assumes valid data has been provided
#
# @return a hash where the keys are a description of the field that was parsed
#         and the values are the data that was actually parsed
##
function parse_version_reply()
{
  local_var reply, ret, pos, len;
  reply = _FCT_ANON_ARGS[0];
  ret = make_array();
  pos = 0;

  #string	description	Text information on the VM version 
  len = getdword(blob:reply, pos:pos);
  pos += 4;
  ret['VM version description'] = substr(reply, pos, pos + len - 1);
  pos += len;
  
  #int	jdwpMajor	Major JDWP Version number 
  ret['Major JDWP version number'] = getdword(blob:reply, pos:pos);
  pos += 4;

  #int	jdwpMinor	Minor JDWP Version number 
  ret['Minor JDWP version number'] = getdword(blob:reply, pos:pos);
  pos += 4;

  #string	vmVersion	Target VM JRE version, as in the java.version property 
  len = getdword(blob:reply, pos:pos);
  pos += 4;
  ret['VM JRE version'] = substr(reply, pos, pos + len - 1);
  pos += len;

  #string	vmName	Target VM name, as in the java.vm.name property 
  len = getdword(blob:reply, pos:pos);
  pos += 4;
  ret['VM name'] = substr(reply, pos, pos + len - 1);
  pos += len;

  return ret;
}

##
# Attempts to connect to the given port and perform a JDWP handshake
#
# @anonparam port JDWP port to connect to
# @remark this function will exit if it fails
#
# @return newly created socket if connection and handshake succeeded
##
function jdwp_init()
{
  local_var port, signature, socket, res;
  port = _FCT_ANON_ARGS[0];

  socket = open_sock_tcp(port);
  if (!socket)
    exit(1, "Failed to open a socket on port "+port+".");

  signature = 'JDWP-Handshake';
  send(socket:socket, data:signature);
  res = recv(socket:socket, length:14);

  if (res != signature)
    exit(0, 'Handshake failed - the service on port ' + port + ' does not look like JDWP.');

  return socket;
}

##
# Closes a JDWP connection
#
# @anonparam socket socket of connection to close
##
function jdwp_close()
{
  local_var socket;
  socket = _FCT_ANON_ARGS[0];

  jdwp_send_recv(socket:socket, cmd_set:JDWP_CMDSET_VM, cmd:JDWP_VM_DISPOSE);
  return close(socket);
}

if (!thorough_tests)
  exit(0, "This plugin only runs when the 'Perofrm thorough tests' setting is enabled.");
if (get_kb_item("global_settings/disable_service_discovery"))
  exit(0, "This plugin only runs when 'Probe services on every port' is enabled.");

port = get_unknown_svc(0);
if (!port) exit(0, 'No unknown services were detected.');
if (known_service(port:port)) exit(0, 'The service on port ' + port + ' has already been identified.');
if (!get_tcp_port_state(port)) exit(0, 'Port ' + port + ' is not open.');

soc = jdwp_init(port);
res = jdwp_send_recv(socket:soc, cmd_set:JDWP_CMDSET_VM, cmd:JDWP_VM_VERSION); # this function exits if it fails
jdwp_close(soc);

register_service(port:port, proto:"jdwp");

if (report_verbosity > 0)
{
  report = '\nNessus was able to run the JDWP \'version\' command which returned the\n' +
           'following information :\n\n';

  ver_info = parse_version_reply(res);
  foreach key (sort(keys(ver_info)))
    report += key + ' : ' + ver_info[key] + '\n';

  security_hole(port:port, extra:report);
}
else security_hole(port);
