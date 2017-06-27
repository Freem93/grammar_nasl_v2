#
# Copyright 2001 by H D Moore <hdmoore@digitaldefense.net>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Output formatting, family change (8/22/09)

include("compat.inc");

if (description)
{
  script_id(10820);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/01/14 12:34:31 $");

  script_cve_id("CVE-1999-0508");

  script_name(english:"F5 Device Default Support Password");
  script_summary(english:"F5 Device Default Support Password");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is protected with default administrative
credentials.");
  script_set_attribute(attribute:"description", value:
"The remote F5 Networks device has the default password set for the
'support' user account.  This account normally provides read/write
access to the web configuration utility.  An attacker could take
advantage of this to reconfigure your systems and possibly gain shell
access to the system with super-user privileges.");
 script_set_attribute(attribute:"solution", value:
"Remove the 'support' account entirely or change the password of this
account to something that is difficult to guess.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SNMP Community Scanner');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2001/12/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2001-2014 Digital Defense Inc.");
  script_family(english:"Misc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 443);
  exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_http_port(default:443);
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

user = 'support';
pass = 'support';

soc = http_open_socket(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

req = string("GET /bigipgui/bigconf.cgi?command=bigcommand&CommandType=bigpipe HTTP/1.0\r\nAuthorization: Basic ", base64(str:user+':'+pass), "\r\n\r\n");
send(socket:soc, data:req);
buf = http_recv(socket:soc);
http_close_socket(soc);

if (!isnull(buf) && ("/bigipgui/" >< buf) && ("System Command" >< buf))
{
  if (report_verbosity > 0)
  {
    report = '\n  User     : ' + user +
             '\n  Password : ' + pass +
             '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
}
else exit(0, "The web server listening on port "+port+" is not affected.");
