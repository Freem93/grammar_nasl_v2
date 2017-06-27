#
# This script was written by H D Moore <hdmoore@digitaldefense.net>
#
# See the Nessus Scripts License for details
#
# Changes by Tenable:
# - Revised plugin family (1/21/2009)

include("compat.inc");

if (description)
{
  script_id(11202);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/12/17 12:13:59 $");

  script_cve_id("CVE-1999-0508");
  script_osvdb_id(870);

  script_name(english:"Enhydra Multiserver Default Password");
  script_summary(english:"Enhydra Multiserver Default Admin Password");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is protected with default administrative
credentials.");
  script_set_attribute(attribute:"description", value:
"This system appears to be running the Enhydra application server
configured with the default administrator password of 'enhydra'.  A
potential intruder could reconfigure this service and use it to obtain
full access to the system.");
  script_set_attribute(attribute:"solution", value:"Set a strong password for the 'admin' account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SNMP Community Scanner');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/01/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2003-2013 Digital Defense Inc.");
  script_family(english:"Web Servers");

  script_dependencie("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 8001);
  exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_http_port(default:8001);
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

banner = get_http_banner(port:port);
if ( ! banner || "Enhydra" >!< banner ) exit(0, "The web server listening on port "+port+" does not look like an Enhydra application server.");

req = http_get(item:"/Admin.po?proceed=yes", port:port);
req = req - string("\r\n\r\n");
req = string(req, "\r\nAuthorization: Basic YWRtaW46ZW5oeWRyYQ==\r\n\r\n");
buf = http_keepalive_send_recv(port:port, data:req);

if ("Enhydra Multiserver Administration" >< buf) security_hole(port);
else audit(AUDIT_LISTEN_NOT_VULN, "Enhydra application server", port);
