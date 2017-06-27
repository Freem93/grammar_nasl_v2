#
# This script was written by H D Moore
# Information about the AP provided by Brian Caswell
#
# Chnages by Tenable :
#
# Added CVSS2 score, revised desc, updated severity.
#

include("compat.inc");

if (description)
{
  script_id(10961);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2014/09/17 14:47:25 $");

  script_cve_id("CVE-1999-0508");
  script_osvdb_id(785);

  script_name(english:"AirConnect Default Password");
  script_summary(english:"3Com AirConnect AP Default Password");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to access the remote wireless access point with default
credentials.");
  script_set_attribute(attribute:"description", value:
"This AirConnect wireless access point still has the default password
set for the web interface. This could be abused by an attacker to gain
full control over the wireless network settings.");
script_set_attribute(attribute:"solution", value:
"Change the password to something difficult to guess via the web
interface.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SNMP Community Scanner');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/05/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);

  script_copyright(english:"This script is Copyright (C) 2002-2014 Digital Defense Inc.");
  script_family(english:"Misc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

function sendrequest (request, port)
{
    local_var reply;
    reply = http_keepalive_send_recv(data:request, port:port);
    if (isnull(reply)) exit(1, "The web server listening on port "+port+" failed to respond.");
    return(reply);
}

#
# The script code starts here
#

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_http_port(default:80);
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

user = 'comcomcom';
pass = 'comcomcom';

req = string("GET / HTTP/1.0\r\nAuthorization: Basic ", base64(str:user+':'+pass), "\r\n\r\n");
reply = sendrequest(request:req, port:port);

if ("SecuritySetup.htm" >< reply)
{
  if (report_verbosity > 0)
  {
    report = '\n  User     : ' + user +
             '\n  Password : ' + pass +
             '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The web server listening on port "+port+" is not affected.");
