#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(23698);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/08/29 21:03:42 $");

  script_name(english:"HP OpenView Storage Mirroring Server Detection");
   
 script_set_attribute(attribute:"synopsis", value:
"An HP OpenView Storage Mirroring service is listening on this port." );
 script_set_attribute(attribute:"description", value:
"The remote host is running HP OpenView Storage Mirroring Daemon.
This service is part of the HP OpenView Management suite." );
 script_set_attribute(attribute:"solution", value:
"If this service is not needed, disable it or filter incoming traffic to 
this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/21");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:openview");
script_end_attributes();

  script_summary(english:"Checks for HP OpenView Storage Mirroring Daemon");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
  script_require_ports(1100);
  exit(0);
}

#

include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

function get_name (s, pos)
{
 local_var ret, len, data;

 if (strlen(s) < 2)
   exit (0);

 len = getword(blob:s, pos:pos);
 if (strlen(s) < pos+len)
   exit (0);

 pos += 2;
 data = substr(s, pos, pos+len-1);
 pos += len;

 ret = NULL;
 ret[0] = data;
 ret[1] = pos;

 return ret;
}


os_name = "nessus";
os_version = "nessus";
c_version = "nessus";
home = "nessus";
path = "nessus";
domain = "nessus";

req =
	mkword (2) +
	mkword (1) +
	mkword (0x2728) +
	mkdword (0) +
	mkdword (0) +
	mkdword (0) +
	mkdword (0) +
	mkdword (0) +
	mkword (0x0d) +
	mkword (0) +
	mkdword (0) +
	mkdword (0) +
	mkdword (0) +
	mkdword (0) +
	mkword (1) +
	mkdword (0xffffffff) +
	mkword (strlen(os_name)) + os_name +
	mkword (strlen(os_version)) + os_version +
	mkword (strlen(c_version)) + c_version +
	mkdword (0x4042a60c) +
	mkdword (0) +
	mkword (0x3ee) +
	mkword (strlen(home)) + home +
	mkword (strlen(path)) + path +
	mkdword (0) +
	mkword (strlen(domain)) + domain;

port = 1100;

if (!get_port_state(port))
  exit(0);


soc = open_sock_tcp (port);
if (!soc)
  exit (0);

send (socket:soc, data:req);
buf = recv (socket:soc, length:4096);

header = hex2raw(s:"0002000200e0000000000000000000000000000000000000000d0000000100000000ffffffff");

if (strlen(buf) < strlen(header))
  exit (0);

s = substr(buf, 0, strlen(header)-1);

if (s != header)
  exit (0);

s = substr(buf, strlen(header), strlen(buf)-1);
pos = 0;

os = get_name(s:s, pos:0);
version = get_name(s:s, pos:os[1]);
pversion = get_name(s:s, pos:version[1]);

report = string ("\n",
		"The following information was extracted from this service :\n",
                "\n",
		"OS              : ", os[0], "\n",
		"OS version      : ", version[0], "\n",
		"Product version : ", pversion[0]);
register_service(port:port, proto:"hp-mirror-svc");
security_note(port:port, extra:report);
