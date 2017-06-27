#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56022);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/04/23 23:04:35 $");

  script_name(english:"OpenVPN Server Detection");
  script_summary(english:"Detects an OpenVPN server");

  script_set_attribute(attribute:"synopsis", value:
"An OpenVPN server is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running an OpenVPN server. Based on its responses,
the remote host appears to be in TLS or preshared key mode.");

  script_set_attribute(attribute:"see_also", value:"http://openvpn.net/");

  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openvpn:openvpn");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2011 - 2014 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_timeout(1800); # because of recv(timeout:30) in preshared mode

  exit(0);
}

include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

function detect(port, proto, preshared)
{
  local_var header, key, len, opcode, report, req, res, session, soc;
  local_var unknown;

  # Don't bother with detection if this service is already identified.
  if (!service_is_unknown(port:port, ipproto:proto))
    return FALSE;

  # Don't bother with detection if nothing is listening on this port.
  if (proto == "tcp")
  {
    if (!get_tcp_port_state(port))
      return FALSE;
  }
  else if (!get_udp_port_state(port))
    return FALSE;

  # OpenVPN fields are big-endian.
  set_byte_order(BYTE_ORDER_BIG_ENDIAN);

  # Use the P_CONTROL_HARD_RESET_CLIENT_V2 opcode.
  opcode = 0x07;

  # Leave the key ID blank, since we're not renegotiating.
  key = 0x00;

  # Choose a local session ID.
  session = mkdword(rand()) + mkdword(rand());

  # Fields we don't understand.
  unknown = raw_string(0x00, 0x00, 0x00, 0x00, 0x00);

  # Stitch the request together.
  header = raw_string((opcode << 3) | key);
  req = header + session + unknown;
	
		   
  if (proto == "tcp")
    req = mkword(strlen(req)) + req;

  # Try to open socket.
  if (proto == "tcp")
    soc = open_sock_tcp(port);
  else
    soc = open_sock_udp(port);
  if (!soc)
    return FALSE;

  # Calculate the minimum length of a response we expect.
  len = 0;
  if (proto == "tcp")
    len += 2;
  len += 1; # Opcode and key.
  len += 8; # Session ID.
  len += 5; # Unknown.

  # Send our reset request to the server, and receive its response.
  if ( ! preshared )
  {
   send(socket:soc, data:req);
   res = recv(socket:soc, length:1024);
  }
  else  res = recv(socket:soc, length:1024, timeout:30);
  close(soc);

  # Verify that the minimum length is what we expect.
  if (strlen(res) < len)
    return FALSE;

  # If TCP, verify the length field matches the packet's length.
  if (proto == "tcp" && getword(blob:res, pos:0) != strlen(res) - 2)
    return FALSE;

  if ( preshared )
  {
   register_service(port:port, ipproto:proto, proto:"openvpn");
   set_kb_item(name:"openvpn/" + port, value:TRUE);
   set_kb_item(name:"openvpn/" + port + "/proto", value:proto);
   set_kb_item(name:"openvpn/" + port + "/" + proto + "/mode", value:"preshared");
   if (report_verbosity > 0)
   {
     report = '\nOpenVPN is running on this port in Pre-Shared mode.\n';
     security_note(port:port, protocol:proto, extra:report);
   }
   else security_note(port:port, protocol:proto);
   return TRUE;
  }
  # Remove the length field so that we may treat both TCP and UDP
  # packets the same.
  if (proto == "tcp")
    res = substr(res, 2);

  # Verify that the opcode is P_CONTROL_HARD_RESET_SERVER_V2.
  if (getbyte(blob:res, pos:0) >> 3 != 0x08)
    return FALSE;

  # Verify that the key is the same as in the request.
  if (getbyte(blob:res, pos:0) & 0x07 != key)
    return FALSE;

  # Verify that the consistent unknown run of bytes is after the
  # session ID.
  unknown = raw_string(0x01, 0x00, 0x00, 0x00, 0x00);
  if (substr(res, 9, 13) != unknown)
    return FALSE;

  # Flag the port as running OpenVPN.
  register_service(port:port, ipproto:proto, proto:"openvpn");
  set_kb_item(name:"openvpn/" + port, value:TRUE);
  set_kb_item(name:"openvpn/" + port + "/proto", value:proto);
  set_kb_item(name:"openvpn/" + port + "/" + proto + "/mode", value:"tls");

  # Report our findings.
  if (report_verbosity > 0)
  {
    report = '\nOpenVPN is running on this port in TLS mode.\n';
    security_note(port:port, protocol:proto, extra:report);
  }
  else security_note(port:port, protocol:proto);

  return TRUE;
}


detected = FALSE;
common = make_list(1194, 5000);

# Try to detect OpenVPN on all its common ports over UDP.
foreach port (common)
{
  if (detect(proto:"udp", port:port))
    detected = TRUE;
}

# Get list of unknown services, if settings permit.
if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery"))
  ports = get_kb_list("Services/unknown");

if (isnull(ports))
  ports = make_list();

# Add to our list the ports that OpenVPN commonly listens on.
foreach port (common)
  ports = add_port_in_list(list:ports, port:port);

if ( ( get_port_state(1194) || get_port_state(5000) ) )
{
 if ( detect(proto:"tcp", port:1194, preshared:TRUE) ||
     detect(proto:"tcp", port:5000, preshared:TRUE) ) detected = TRUE;
 sleep(1);
}

# Try to detect OpenVPN on TCP.
foreach port (ports)
{
  if (detect(proto:"tcp", port:port))
    detected = TRUE;
}


if (!detected)
  exit(0, "OpenVPN was not detected on the remote host.");
