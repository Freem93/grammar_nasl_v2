#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23972);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/10/27 17:45:53 $");

  script_name(english:"Teredo Server Detection");
  script_summary(english:"Detects a Teredo server.");

 script_set_attribute(attribute:"synopsis", value:
"A Teredo server is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a Teredo server. Teredo is a protocol for
tunneling IPv6 over UDP, and is used to give nodes the ability to
obtain IPv6 connectivity behind IPv4 network address translation (NAT)
devices. A Teredo server is a node that is connected to both IPv4 and
IPv6 networks." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Teredo_tunneling" );
 script_set_attribute(attribute:"see_also", value:"http://www.ietf.org/rfc/rfc4380.txt" );
 # https://web.archive.org/web/20071209000951/http://www.ietf.org/internet-drafts/draft-ietf-v6ops-teredo-security-concerns-01.txt
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5b3b43f5" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired. When full IPv6
connectivity is available, the Teredo server should be disabled." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/01/04");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_require_udp_ports(3544);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");

if ( TARGET_IS_IPV6 ) exit(0);
if ( islocalhost() ) exit(1, "Cannot test this plugin against localhost.");

port = 3544;
if ( ! get_udp_port_state(port) ) exit(0);
soc = open_sock_udp(port);
if (!soc) exit(0);

# Send a router solicitation request.
client_id = "";                        # client identifier
auth = "";                             # authentication value
nonce = mkdword(rand()) + mkdword(rand());
src_addr = mkword(0xfe80) +            #  source address
  mkword(0x0000) +
  mkword(0x0000) +
  mkword(0x0000) +
  mkword(0x0000) +
  mkword(0xffff) +
  mkword(0xffff) +
  mkword(0xffff);
dst_addr = mkword(0xff02) +            # destination address
  mkword(0x0000) +
  mkword(0x0000) +
  mkword(0x0000) +
  mkword(0x0000) +
  mkword(0x0000) +
  mkword(0x0000) +
  mkword(0x0002);

req = 
                                       # authentication header
   mkbyte(0) + mkbyte(1) +
   mkbyte(strlen(client_id)) +         #  ID-len
   mkbyte(strlen(auth)) +              #  AU-len
   client_id +
   auth +
   nonce +
   mkbyte(0) +                         #  confirmation byte
                                       # IPv6 packet
   mkbyte(0x60) +                      #  version
   mkbyte(0) +                         #  traffic class
   mkword(0) +                         #  flowlabel
   mkword(0x0008) +                    #  payload length
   mkbyte(0x3a) +                      #  next header (3a => ICMPv6)
   mkbyte(255) +                       #  hop limit
   src_addr +
   dst_addr +
                                       #  ICMPv6 packet
    mkbyte(133) +                      #   type (133 => router solicitation)
    mkbyte(0) +                        #   code
    mkword(0x7d37) +                   #   checksum
    mkword(0) + mkword(0);             #   padding

filter = string(
  "udp and ",
  "src port ", port, " and ",
  "dst port ", get_source_port(soc)
);
res = send_capture(socket:soc, data:req, pcap_filter:filter);
if (res == NULL) exit(0);
res = get_udp_element(udp:res, element:"data");

# If ...
if (
  strlen(res) > 21 && 
  # the response starts with an authentication header with our nonce 
  # or an origin header and ...
  (
    getbyte(blob:res, pos:0) == 0 && 
    (
      (getbyte(blob:res, pos:1) == 0 && stridx(res, nonce) == 4) || 
      getbyte(blob:res, pos:1) == 1
    )
  ) &&
  # there's an ICMPv6 router advertisement following our source address.
  mkbyte(0x3a) >< res && (src_addr + mkbyte(134) + mkbyte(0)) >< res
)
{
  # Register the service.
  register_service(port:port, ipproto:"udp", proto:"teredo");

  # Collect some info for the report.
  info = "";
  icmpv6 = strstr(res, src_addr + mkbyte(134)) - src_addr;
  options = substr(icmpv6, 16);
  while (strlen(options))
  {
    type = getbyte(blob:options, pos:0);
    len = getbyte(blob:options, pos:1) * 8;
    if (len > strlen(options)) break;

    if (type == 3)
    {
      prefix_len = getbyte(blob:options, pos:2);
      valid_lifetime = getdword(blob:options, pos:4);
      if (valid_lifetime == -1) valid_lifetime = "infinity";
      pref_lifetime = getdword(blob:options, pos:8);
      if (pref_lifetime == -1) pref_lifetime = "infinity";
      # reserved = getdword(blob:options, pos:12);
      prefix = "";
      for (i=0; i<(prefix_len/8); i++)
      {
        prefix += hexstr(substr(options, 16+i, 16+i));
        if (i % 2) prefix += ":";
      }
      # nb: the prefix should consist of "2001:0000:" (the
      #     global Teredo IPv6 service prefix) followed by
      #     the remote's IPv4 address, but Miredo for example
      #     allows it to be changed easily.
      if (prefix && (report_paranoia < 2 && "2001:0000:" >< prefix))
        info += '  Prefix             : ' + prefix + ':' + '\n' +
                '  Valid lifetime     : ' + valid_lifetime + '\n' +
                '  Preferred lifetime : ' + pref_lifetime + '\n';
    }
    else if (type == 5)
    {
      mtu = getdword(blob:options, pos:4);
      if (mtu)
        info += '  MTU                : ' + mtu + '\n';
    }

    options = substr(options, len);
  }

  if (info)
    report = string(
      "Nessus was able to gather the following information from\n",
      "the remote Teredo server :\n",
      "\n",
      info
    );
  else report = NULL;
  security_note(port:port, proto:"udp", extra:report);
}
