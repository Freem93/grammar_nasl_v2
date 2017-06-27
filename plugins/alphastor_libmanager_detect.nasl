#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(33280);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2011/03/11 21:18:07 $");

  script_name(english:"EMC AlphaStor Library Manager Detection");
  script_summary(english:"Detects an AlphaStor Library Manager robotd service");

 script_set_attribute(attribute:"synopsis", value:
"There is a tape backup manager installed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a EMC AlphaStor Library Manager service.
AlphaStor is a tape backup management and library sharing for EMC
NetWorker." );
 script_set_attribute(attribute:"see_also", value:"http://www.emc.com/products/detail/software/alphastor.htm" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/07/01");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 3500);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");


function mk_command(cmd, s)
{
 local_var len;

 len = strlen(s);

 return mkbyte(cmd + 0x31) + s + crap(data:mkbyte(0), length:0x200-len) + mkbyte(0);
}


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  ) {
  port = get_unknown_svc(3500);
  if ( ! port ) exit(0);
}
else port = 3500;
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


req = mk_command(cmd:0x20, s:"");
send(socket:soc, data:req);

res = recv(socket:soc, length:0x202, min:0x202);
close(soc);
if (isnull(res) || strlen(res) != 0x202) 
  exit(0);

res = substr(res, 5, strlen(res)-1);
if ("robotd~robotd~CLIENT~" >!< res)
  exit(0);

register_service(port:port, ipproto:"tcp", proto:"alphastor-libmanager");

platform = ereg_replace(pattern:"robotd~robotd~CLIENT~(.*)~.*", string:res, replace:"\1");

if (platform)
{
 report = string ("OS Type: ", platform, "\n");
 security_note(port:port, extra:report);
 set_kb_item(name:"AlphaStor/LibraryManager/"+port+"/OS", value:platform);
}
else
 security_note(port:port);

