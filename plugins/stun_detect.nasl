#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45580);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/10/27 17:45:53 $");

  script_name(english:"STUN Detection");
  script_summary(english:"Sends a STUN Binding request.");

  script_set_attribute(attribute:"synopsis", value:"A STUN server is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote service supports the STUN (Session Traversal Utilities for
NAT) protocol as described in RFC 5389. STUN helps client software
behind a NAT router discover the external public address and the
behavior of the router.

Note that an earlier version of the protocol used a different acronym
- 'Simple Traversal of User Datagram Protocol (UDP) Through Network
Address Translators (NATs)' - as specified in RFC 3489.");
  script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Session_Traversal_Utilities_for_NAT");
  script_set_attribute(attribute:"see_also", value:"http://tools.ietf.org/html/rfc5389");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_require_udp_ports(3478,3479);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");

function ip6_addr()
{
  local_var str, i, oct, ret;
  str = _FCT_ANON_ARGS[0];
  for ( i = 0 ; i < strlen(str) ; i += 4 )
  {
    if ( strlen(ret) > 0 ) ret += ":";
    oct = substr(str, i, i + 3);
    while ( strlen(oct) && oct[0] == "0" ) oct = substr(oct, 1, strlen(oct) - 1);
    if ( oct == "0" ) oct = "";
    ret += oct;
  }
  ret = ereg_replace(pattern:"::+", replace:"::", string:ret);
  return ret;
}

function extract_addr(a)
{
  local_var	t, j, p, ip;

  t = getword(blob: a, pos: 0);
  j = 4;
  if (t == 1)
    ip = strcat(ord(a[j]),'.', ord(a[j+1]),'.', ord(a[j+2]),'.', ord(a[j+3]));
  else if (t == 2)
    ip = ip6_addr(substr(a, j, j + 15));
  else
  {
    debug_print("Unhandled address type '", t, "'.");
    return NULL;
  }
  p  = getword(blob: a, pos: j);
  return strcat(ip, ':', p);
}

function test(port)
{
  local_var	tid, msg, i, r, soc, len, l, z, v, j, txt, a, attr;

  if (! get_udp_port_state(port))
  {
    debug_print("UDP port ", port, " is not open.");
    return 0;
  }
  if (! service_is_unknown(port: port, ipproto: "udp"))
  {
    debug_print("The service on UDP port ", port, " is already known.");
    return 0;
  }

  soc = open_sock_udp(port);
  if (! soc)
  {
    debug_print("Can't open socket on UDP port ", port, ".");
    return 0;
  }

  tid = '';
  for (i = 0; i < 16; i ++) tid += raw_string(rand() % 256);
  msg =
      '\x00\x01' +	# Binding request
      '\x00\x08' +	# Message length
      tid +
      # Attributes
      '\x00\x03' +	# CHANGE-REQUEST
      '\x00\x04' +	# Length
      '\0\0\0\0';		# Change IP: not set, Change Port: not set

  send(socket: soc, data: msg);
  r = recv(socket: soc, length: 512);
  close(soc);
  # dump(dtitle: "STUN", ddata: r);
  l = strlen(r);

  if (l < 20)
  {
    debug_print("No/short answer (", l, ") from UDP port ", port, ".");
    return 0;
  }

  if (r[0] != '\x01' || r[1] != '\x01')
  {
    debug_print("Not a STUN binding response.");
    return 0;
  }

  len = getword(blob: r, pos:2);
  if (l != len + 16 + 4)
  {
    debug_print("Inconsistent message length.");
    return 0;
  }

  z = substr(r, 4, 4+15);
  if (z != tid)
  {
    debug_print("Wrong TID.");
  }

  i = 2 + 2 + 16;
  txt = '';
  while (i < l)
  {
    # dump(dtitle: "STUN"+i, ddata: substr(r, i));
    if (i + 4 > l)
    {
      debug_print('Malformed packet.\n');
      return 0;
    }
    attr = getword(blob:r, pos: i);
    len = getword(blob:r, pos: i+2);
    i += 4;
    if (i + len > l)
    {
      debug_print('Malformed packet.\n');
      return 0;
    }

    if (attr == 1)
    {
      a = extract_addr(a: substr(r, i, i + len - 1));
      if (a) txt = strcat(txt, 'MAPPED-ADDRESS = ', a, '\n');
    }
    else if (attr == 4)
    {
      a = extract_addr(a: substr(r, i, i + len - 1));
      if (a) txt = strcat(txt, 'SOURCE-ADDRESS = ', a, '\n');
    }
    else if (attr == 5)
    {
      a = extract_addr(a: substr(r, i, i + len - 1));
      if (a) txt = strcat(txt, 'CHANGED-ADDRESS = ', a, '\n');
    }
    else if (attr == 32802)
    {
      if (len > 0)
      txt = strcat(txt, 'SERVER = ', substr(r, i, i + len - 2), '\n');
    }
    else
      debug_print("Unhandled attribute '", attr, "'.");
    i += len;
  }
  if (COMMAND_LINE) display(txt);
  security_note(port: port, proto: "udp", extra: '\n'+txt);
  register_service(port:port, ipproto:"udp", proto:"stun");
  return 1;
}

set_byte_order(BYTE_ORDER_BIG_ENDIAN);

test(port: 3478);
test(port: 3479);
