#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22094);
  script_version("$Revision: 1.14 $");

  script_name(english:"Check Point FireWall-1 ICA Service Detection");
  script_summary(english:"Checks for Check Point ICA Service");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is a firewall." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Check Point FireWall-1 and is operating a
web server on this port for its internal certificate authority (ICA),
which provides users with certificate revocation lists and registers
users when using the Policy Server. 

Note that it is not known whether it is possible to disable this
service or limit its access to only certain interfaces or addresses." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/07/27");
 script_cvs_date("$Date: 2012/08/13 17:27:40 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:checkpoint:firewall-1");
 script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2006-2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 18264);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:18264, embedded:TRUE);

banner = get_http_banner(port:port, exit_on_fail: 1);
if ("Server: Check Point SVN" >< banner)
{
  res = http_get_cache(item:"/", port:port, exit_on_fail: 1);

  if ("<TITLE>Check Point Certificate Services</TITLE>" >< res)
  {
    security_note(port);

    register_service(port:port, ipproto:"tcp", proto:"cp_ica");
  }
}
