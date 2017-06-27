#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(50971);
 script_version("$Revision: 1.4 $");
 script_cvs_date("$Date: 2014/01/07 21:38:30 $");

 script_name(english:"Vuze Detection");
 script_summary(english:"Vuze detection");

 script_set_attribute(attribute:"synopsis", value:"A file-sharing service is running on the remote port.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Vuze, a BitTorrent client used
for peer-to-peer file-sharing.

Note that, due to the peer-to-peer nature of the application, any user
connecting to the P2P network may consume a large amount of
bandwidth.");
 script_set_attribute(attribute:"solution", value:
"Make sure that the use of this program agrees with your organization's
acceptable use and security policies. 

Note that filtering traffic to or from this port is not a sufficient
solution since the software can use a random port.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/02");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
 script_family(english:"Peer-To-Peer File Sharing");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");


# some vuze dht action codes
VUZE_DHT_PING_REQ         = 1024;
VUZE_DHT_PING_REPLY       = 1025;
VUZE_DHT_FIND_NODE_REQ    = 1028;
VUZE_DHT_FIND_NODE_REPLY  = 1029;


function sock_sendrecv(soc,data)
{
  send(socket:soc, data:data);
  return recv(socket:soc,length:4096);
}

function unixtime_mili()
{
  local_var i,c, ret, utime;

  utime = uint(unixtime());
  i = uint(0xFFFFFFFF) / uint(1000);
  c = utime / i;
  ret = mkdword(c) + mkdword(utime * 1000);

  return ret;
}


# create a req header
function vuze_dht_req_hdr(conid, action, xid, proto_ver, local_ip, local_port)
{
  local_var vid, netid, lproto_ver, inst_id, time,hdr;


  vid = mkbyte(0);
  netid = mkdword(0);
  lproto_ver = mkbyte(0x32);
  inst_id = mkdword(rand());

  # unixtime() in miliseconds
  # it appears that dht_ping and dht_findnode will still
  # get response even if this field is set to random
  time = unixtime_mili();

  hdr = conid +
        action +
        xid +
        proto_ver +
        vid +
        netid +
        lproto_ver +
        mkbyte(strlen(local_ip)) +
        local_ip  +
        local_port +
        inst_id +
        time;

  return hdr;
}


# send vuze dht ping and wait for reply
# return:
#   success - network coordinates of the replying node
#   failure - NULL
#
function vuze_ping_sendrecv(soc, conid, xid)
{
  local_var res, ping, ip, port;

  ip   = this_host_raw();
  port = mkword(get_source_port(soc));


  ping =  vuze_dht_req_hdr(conid:conid,
                           xid: xid,
                           action:mkdword(VUZE_DHT_PING_REQ),
                           proto_ver:mkbyte(0x32),
                           local_ip: ip,
                           local_port:port);

  return sock_sendrecv(soc:soc, data:ping);
}

# find 20 nodes closest to @target
# return:
#   success - network coordinates of the replying node along
#             with 20 nodes that are closest to the target. each
#             node contains an IP and a port number.
#   failure - NULL
#
function vuze_find_node_sendrecv(soc, conid, xid, target)
{
  local_var res, find_node, ip, port, hdr;
  local_var node_id;

  ip   = this_host_raw();
  port = mkword(get_source_port(soc));


  hdr =  vuze_dht_req_hdr(conid:conid,
                          xid: xid,
                          action:mkdword(VUZE_DHT_FIND_NODE_REQ),
                          proto_ver:mkbyte(0x32),
                          local_ip: ip,
                          local_port:port);
  find_node = hdr +
              mkbyte(strlen(target)) + target +
              mkdword(0) +  # node status
              mkdword(0);   # dht size

  return sock_sendrecv(soc:soc, data:find_node);
}

#
# by default, vuze uses the same listening port for TCP and UDP connections
# vuze DHT operates on UDP

port = get_unknown_svc();
if (!port) exit(0, "There are no unknown services.");

if (known_service(port:port, ipproto:"udp"))
  exit(0, "The service listening on UDP port "+port+" is already known.");

if (!get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if ( ! soc ) exit(0,"failed to create socket on port " + port + "." );

conid = rand_str(length:8);
# MSB of the connection id is required to be set
conid[0] = raw_string(ord(conid[0]) | 0x80);

xid = rand();
res = vuze_ping_sendrecv(soc:soc, conid:conid, xid:mkdword(xid));
close(soc);

if(isnull(res)) exit(0, "No response received to a Vuze DHT ping on UDP port " + port + ".");

if (
  getdword(blob:res,pos:0) == VUZE_DHT_PING_REPLY &&
  getdword(blob:res,pos:4) == xid                 &&
  substr(res, 8, 15) == conid
)
{
  security_note(port:port);
  register_service(port:port, ipproto:"udp", proto:"vuze");
  register_service(port:port, ipproto:"tcp", proto:"vuze");
  exit(0);
}
else exit(0, "The response from port "+port+" does not look like a Vuze DHT ping reply.");
