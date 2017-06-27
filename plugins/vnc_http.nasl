#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
#
# See the Nessus Scripts License for details
#

include("compat.inc");

if (description)
{
 script_id(10758);
 script_version("$Revision: 1.23 $");
 script_cvs_date("$Date: 2013/10/11 14:22:50 $");

 script_name(english:"VNC HTTP Server Detection");
 script_summary(english:"Detects the presence of VNC HTTP");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a remote display software (VNC).");
 script_set_attribute(attribute:"description", value:
"The remote host is running VNC (Virtual Network Computing), which uses
the RFB (Remote Framebuffer) protocol to provide remote access to
graphical user interfaces and thus permits a console on the remote host
to be displayed on another.");
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Vnc");
 script_set_attribute(attribute:"solution", value:
"Make sure use of this software is done in accordance with your
organization's security policy and filter incoming traffic to this
port.");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/09/14");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001-2013 Alert4Web.com");
 script_family(english:"Service detection");

 script_dependencie("find_service1.nasl", "httpver.nasl");
 script_require_ports("Services/www", 5800, 5801, 5802);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

function probe(port)
{
 local_var res;

 res = http_get_cache(port:port, item:'/');
 if (res)
 {
  if (egrep(pattern:"vncviewer\.(jar|class)", string:res, icase:TRUE))
  {
   security_note(port);
   set_kb_item(name:"www/vnc", value:TRUE);
   set_kb_item(name:"www/"+port+"/vnc", value:TRUE);
  }
 }
}

ports = add_port_in_list(list:get_kb_list("Services/www"), port:5800);
ports = add_port_in_list(list:ports, port:5801);
ports = add_port_in_list(list:ports, port:5802);

foreach port (ports)
{
  probe(port:port);
}

