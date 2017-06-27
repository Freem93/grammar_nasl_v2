#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) 
{
  script_id(33392);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2012/08/01 20:46:27 $");

  script_name(english:"Microsoft Dynamics GP Distributed Process Manager Detection");
  script_summary(english:"Detects Microsoft Dynamics GP Distributed Process Manager");

 script_set_attribute(attribute:"synopsis", value:
"There is a business accounting software installed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Microsoft Dynamics GP Distributed Process
Manager. Dynamics GP is a business accounting and management software
solution from Microsoft." );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/dynamics/gp/default.mspx" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/07/02");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:microsoft:dynamics_gp");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2012 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 1351);

  exit(0);
}


include ("global_settings.inc");
include ("misc_func.inc");
include ("byte_func.inc");

function mkstring(s, msize)
{
 local_var len;

 len = strlen(s);
 return mkbyte(len) + s + crap(data:mkbyte(0), length:msize-(len+1));
}

port = 1351;
if (!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

type = 4;

data = 
     mkdword(1) +
     mkdword(0) +
     mkdword(53);

req =
    mkdword(1) +  # Magic
    mkstring(s:"nessus", msize:0x52) +
    mkdword(rand()) + # Unknown 
    mkdword(1) ;  # DPS code ?

len = strlen(req) + strlen(data) + 12;

req = req +
    mkdword(len) +
    mkdword(type) +
    data;

req = 
    mkdword(1) +
    mkdword(strlen(req)) +
    mkdword(0x1234) +
    req;

send(socket:soc, data:req);

buf = recv(socket:soc, length:1024);
if (strlen(buf) != 130) exit(0);

magic = getdword(blob:buf, pos:0);
len = getdword(blob:buf, pos:4);

if (magic != 1 || (len + 12) != strlen(buf)) exit(0);

len = ord(buf[16]);

register_service(port:port, ipproto:"tcp", proto:"microsoft-dpm");

if (len > 0)
{
 name = substr(buf, 17, 17+len-1);

 report = string ("Host Name : ", name, "\n");
 security_note(port:port, extra:report);
}
else
 security_note(port:port);

