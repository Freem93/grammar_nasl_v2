#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23832);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/10/27 17:45:53 $");

  script_name(english:"CA BrightStor ARCserve Backup Discovery Service Detection");
  script_summary(english:"Detects BrightStor ARCserve Backup discovery service over UDP.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running BrightStor ARCserve Backup's Discovery
Service.");
  script_set_attribute(attribute:"description", value:
"The remote server appears to be running BrightStor ARCserve Backup, an
enterprise class backup program. 

The software's Discovery Service listens for broadcast packets from
other BrightStor servers on the local network to learn about their
existence.");
  script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:arcserve_backup");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_require_udp_ports(41524);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");

if ( islocalhost() ) exit(1, "Cannot test this plugin against localhost.");
port = 41524;
if ( ! get_udp_port_state(port) ) exit(0);
soc = open_sock_udp(port);
if (!soc) exit(0);

# Send a service request to try to register a new backup server.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);
myip = split(this_host(), sep:".", keep:FALSE);
name = "DISCOVERY";                    # server name
domain = "NESSUS";                     # domain name

req = mkbyte(0x9b) +                   # magic
  name +                               # name null-padded to 16 bytes
    crap(
      data:raw_string(0), 
      length:16-strlen(name)
    ) +
  mkdword(0x85) +
  mkbyte(int(myip[0])) +               # my IP
    mkbyte(int(myip[1])) +
    mkbyte(int(myip[2])) +
    mkbyte(int(myip[3])) + 
  domain +                             # domain null-padded to 16 bytes
    crap(
      data:raw_string(0), 
      length:16-strlen(domain)
    ) +
  mkbyte(1) +
  mkbyte(0) +
  mkbyte(0xc8) + 
  mkbyte(0x6b) + 
  mkbyte(0x17) + 
  mkbyte(0x46) + 
  mkbyte(0) + 
  mkbyte(0) +
  mkbyte(0) +
  mkdword(0x85) +
  mkdword(0x0f) +
  mkbyte(1) +
  mkbyte(0x0b) +
  mkbyte(0xf4) +
  mkbyte(0x0b) +
  mkdword(2) +
  mkdword(5) +
  "00000001" +
  mkbyte(0) +
  mkbyte(0xef) +
  mkbyte(0xc3) +
  mkbyte(0x06) +
  mkbyte(0x16) +
  crap(data:raw_string(0), length:16);

filter = string(
  "udp and ",
  "src host ", get_host_ip(), " and ",
  "dst port ", port
);
res = send_capture(socket:soc, data:req, pcap_filter:filter);
if (res == NULL) exit(0);
res = get_udp_element(udp:res, element:"data");
close(soc);

# If ...
if (
  # the string is long enough and ...
  strlen(res) >= 99 &&
  # the initial byte is 0x9c
  getbyte(blob:res, pos:0) == 0x9c &&
  # the dwords at 0x11 and 0x32 are 0x85
  getdword(blob:res, pos:0x11) == 0x85 &&
  getdword(blob:res, pos:0x32) == 0x85
)
{
  # Register and report the service.
  register_service(port:port, ipproto:"udp", proto:"casdscsvc");

  # Extract some interesting pieces of information.
  info = "";
  ip = getbyte(blob:res, pos:0x15) + '.' +
       getbyte(blob:res, pos:0x16) + '.' +
       getbyte(blob:res, pos:0x17) + '.' +
       getbyte(blob:res, pos:0x18);
  info += '  Server IP           : ' + ip + '\n';
  name = substr(res, 1);
  if (name) name = name - strstr(name, raw_string(0));
  if (name) info += '  Primary server name : ' + name + '\n';
  domain = substr(res, 0x19);
  if (domain) domain = domain - strstr(domain, raw_string(0));
  if (domain) info += '  Backup domain       : ' + domain + '\n';
  ver = 'r' + getbyte(blob:res, pos:0x3b) + '.' + getbyte(blob:res, pos:0x3a) +
        ' (build ' + getword(blob:res, pos:0x3c) + ')';
  info += '  Version             : ' + ver + '\n';

  # Save the version in the KB and report what we found.
  set_kb_item(name:"ARCSERVE/Discovery/Version", value:ver);

  report = string(
    "\n",
    "Here is some information that Nessus was able to obtain from BrightStor\n",
    "ARCserve Backup on the remote host :\n",
    "\n",
    info
  );
  security_note(port:port, proto:"udp", extra:report);
}
