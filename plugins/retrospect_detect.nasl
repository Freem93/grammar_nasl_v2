#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20995);
  script_version("$Revision: 1.14 $");

  script_name(english:"Retrospect Client Detection");
  script_summary(english:"Detects a Retrospect Client");

 script_set_attribute(attribute:"synopsis", value:
"There is a backup client installed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a Retrospect backup client. Retrospect 
is a commercial backup product from EMC / Dantz." );
 script_set_attribute(attribute:"see_also", value:"http://www.emcinsignia.com/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/03");
 script_cvs_date("$Date: 2011/03/11 21:18:09 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 497);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");


function getosinfo (info)
{
 local_var major, minor;

 major = info >>> 16;
 minor = info & 0xFFFF;

 if (major > 10)
   return "NetWare";

 if (major >= 2)
   return "Windows";

 if (major == 0)
 {
  if (minor == 0)
    return "RedHat Linux";

  if (minor == 1)
    return "Solaris";

  if ((minor >> 8) == 0x10)
    return string ("MacOS 10.", (minor >> 4) & 0x0F, ".", minor & 0xF);

  else
    return "Unknown Unix";
 }

 return "Unknown";
}


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  ) {
  port = get_unknown_svc(497);
  if ( ! port ) exit(0);
}
else port = 497;
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Packet sent by the server to test a client.
req = raw_string(
  0x00, 0x65, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
);
send(socket:soc, data:req);


# Read the response.
res = recv(socket:soc, length:1024);
close(soc);
if (isnull(res)) exit(0);


# It's a Retrospect client if...
if (
  # the size is correct.
  strlen(res) == 230 &&
  # the initial byte sequence is correct.
  substr(res, 0, 7) == raw_string(0x00, 0xc9, 0x00, 0x00, 0x00, 0x00, 0x00, 0xda) 
) {
  # Extract some interesting bits of info.
  set_byte_order(BYTE_ORDER_BIG_ENDIAN);
  ostype = getdword(blob:res, pos:54);

  name = substr(res, 118);
  name = name - strstr(name, raw_string(0x00));

  ver = substr(res, 214);
  ver = ver - strstr(ver, raw_string(0x00));

  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"retrospect");
  register_service(port:port, ipproto:"udp", proto:"retrospect");

  set_kb_item(name:"Retrospect/"+port+"/Version", value:ver);

  report = string(
    "  Client Name : ", name, "\n",
    "  Version     : ", ver, "\n"
  );
  if (ver =~ "^([0-6]\.|7\.[0-5]\.)")
  {
    set_kb_item(name:"Retrospect/"+port+"/OSType", value:ostype);

    report = string(
      report,
      "  OS Type     : ", getosinfo (info:ostype), "\n"
    );
  }
  security_note(port:port, extra:report);
}
