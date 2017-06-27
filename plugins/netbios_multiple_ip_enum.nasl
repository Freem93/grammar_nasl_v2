#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(43815);
  script_version("$Revision: 1.7 $");

  script_name(english:"NetBIOS Multiple IP Address Enumeration");
  script_summary(english:"Tries to discover if the remote host has multiple IPs");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is configured with multiple IP addresses."
  );
  script_set_attribute(
    attribute:"description",
    value:
"By sending a special NetBIOS query, Nessus was able to detect the use
of multiple IP addresses on the remote host.  This indicates the host
may be running virtualization software, a VPN client, or has multiple
network interfaces."
  );
  script_set_attribute(
    attribute:"solution",
    value:"n/a"
  );
  script_set_attribute(
    attribute:"risk_factor",
    value:"None"
  );
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/01/06");
 script_cvs_date("$Date: 2011/09/02 15:04:40 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  script_require_udp_ports("Services/udp/netbios-ns", 137);
  script_dependencies("netbios_name_get.nasl");
  script_require_keys("SMB/name");

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("byte_func.inc");


# taken from lltd_discover.nasl
function raw_to_ipv4()
{
  local_var i;
  local_var ip;
  local_var ret;

  ip = _FCT_ANON_ARGS[0];
  if ( strlen(ip) != 4 ) return NULL;
  for ( i = 0 ; i < 4 ; i ++ )
  {
   if ( ret ) ret += ".";
   ret += ord(ip[i]);
  }

  return ret;
}


name = kb_smb_name();
port = get_kb_item('Services/udp/netbios-ns');
if (!port) port = 137;

if (!get_udp_port_state(port))
  exit(0, 'UDP port '+port+' is not open.');

soc = open_sock_udp(port);
if (!soc) exit(1, "Failed to open a socket on UDP port "+port+".");

txid = mkword(rand() % 0x10000);
req = 
  txid+            # transaction ID
  mkword(0x0100)+  # flags
  mkword(0x0001)+  # questions
  mkword(0x0000)+  # answer RRs
  mkword(0x0000)+  # authority RRs
  mkword(0x0000)+  # additional RRs
  netbios_encode(data:name, service:0x00)+mkbyte(0x00)+  #nb name
  mkword(0x0020)+  # type
  mkword(0x0001);  #class

send(socket:soc, data:req);
res = recv(socket:soc, length:65535);
if (isnull(res)) exit(1, 'The service on UDP port '+port+' did not respond.');

idx = 0;

# First, verify the transaction ID
res_txid = substr(res, idx, 1);
idx += 2;
if (txid != res_txid)
  exit(1, 'Unexpected transaction ID received from UDP port '+port+'.');

# Skip over the flags, questions, RRs, NB name, etc
idx += 44;
if (idx >= strlen(res))
  exit(1, 'Truncated packet received on UDP port '+port+'.');

# Gets type, then skips over to the data length field
type = getword(blob:res, pos:idx);
idx += 8;
if (type != 0x20)
  exit(1, 'Unexpected type: '+type);
if (idx >= strlen(res))
  exit(1, 'Truncated packet received on UDP port '+port+'.');

data_len = getword(blob:res, pos:idx);
idx += 2;
if (idx >= strlen(res))
  exit(1, 'Truncated packet received on UDP port '+port+'.');
if (data_len != strlen(res) - idx)
  exit(1, 'Data length mismatch.');

data = substr(res, idx, idx+data_len-1);
ip_strs = make_list();

# Parses each IP address, which should be preceded by a 16-bit flags field
for (i = 0; i < data_len; i += 6)
{
  flags = getword(blob:data, pos:i);  # ignored
  ip = substr(data, i+2, i+5);
  ip = raw_to_ipv4(ip);
  if ( isnull(ip) ) continue;
  ip_strs = make_list(ip_strs, ip);
  set_kb_item(name: "Host/Netbios/IP", value: ip);
}

if (max_index(ip_strs) > 1)
{
  if (report_verbosity > 0)
  {
    report = '\nThe remote host appears to be using the following IP addresses :\n\n';
    foreach ip (ip_strs)
      report += '  - ' + ip + '\n';
    security_note(proto:"udp", port:port, extra:report);
  }
  else security_note(proto:"udp", port:port);
  exit(0);
}
else exit(0, "The remote host does not appear to have multiple IP addresses.");
