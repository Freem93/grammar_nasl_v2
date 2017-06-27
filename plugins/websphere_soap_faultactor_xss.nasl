#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23649);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2015/01/16 03:36:09 $");

  script_cve_id("CVE-2006-2431");
  script_bugtraq_id(17919);
  script_osvdb_id(30944);

  script_name(english:"IBM WebSphere Application Server SOAP Connector Error Page XSS");
  script_summary(english:"Checks for an XSS flaw in WebSphere Application Server's SOAP Connector");

  script_set_attribute(attribute:"synopsis", value:
"The remote SOAP server is vulnerable to a cross-site scripting
attack.");
  script_set_attribute(attribute:"description", value:
"The remote SOAP server fails to sanitize user input via the URI
before using it to generate dynamic XML content in an error page.  An
unauthenticated, remote attacker may be able to leverage this issue to
inject arbitrary XML into a user's browser.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/450704/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/search.wss?rs=0&q=PK16602&apar=only");
  script_set_attribute(attribute:"solution", value:
"Apply version 5.0.2 Cumulative Fix 17 / 5.1.1 Cumulative Fix 12 /
6.0.2 Fix Pack 9, depending on the installed version of IBM WebSphere
Application Server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("soap_detect.nasl");
  script_require_ports("Services/soap_http", 8880);
  script_require_keys("www/WebSphere");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_kb_item("Services/soap_http");
if (!port) port = 8880;
if (!get_port_state(port)) exit(0);


# Make sure the banner is for WebSphere.
banner = get_http_banner(port:port);
if (!banner || "Server: WebSphere Application Server" >!< banner) exit(0);


# Send a request to exploit the flaw.
xss = string("/<nessus>", SCRIPT_NAME, "</nessus>");
w = http_send_recv3(method:"GET", item:xss, port:port);
if (isnull(w)) exit(0);
res = w[2];

# There's a problem if our exploit appears in 'faultactor' as-is.
if (string("<faultactor>", xss, "</faultactor>") >< res) 
{
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}

