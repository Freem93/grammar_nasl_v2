#
# This script was written by Matt Moore <matt@westpoint.ltd.uk>
#
#   - Added Synopsis, Reference, CVSS Vector
#   - Modified Description

# Changes by Tenable:
# - Standardized title (4/2/2009)
# - Added Synopsis, Referece, CVSS Vector/Modified Description (4/8/2009)


include("compat.inc");

if (description)
{
 script_id(10938);
 script_version("$Revision: 1.30 $");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");

 script_cve_id("CVE-2002-0061");
 script_bugtraq_id(4335);
 script_osvdb_id(769);

 script_name(english:"Apache on Windows < 1.3.24 / 2.0.x < 2.0.34 DOS Batch File Arbitrary Command Execution");
 script_summary(english:"Tests for presence of Apache Command execution via .bat vulnerability");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote command execution
vulnerability.");
 script_set_attribute(attribute:"description", value:
"Apache for Win32 prior to 1.3.24 and 2.0.x prior to 2.0.34-beta is
shipped with a default script, '/cgi-bin/test-cgi.bat', that allows an
attacker to remotely execute arbitrary commands on the host subject to
the permissions of the affected application. 

An attacker can send a pipe character '|' with commands appended as
parameters, which are then executed by Apache.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Mar/334");
 script_set_attribute(attribute:"see_also", value:"http://www.apacheweek.com/issues/02-03-29#apache1324");
 script_set_attribute(attribute:"solution", value:"Upgrade to Apache web server 1.3.24 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/03/21");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/04/18");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2002-2016 Matt Moore");
 script_family(english:"Web Servers");

 script_dependencie("http_version.nasl", "os_fingerprint.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

# Check makes request for cgi-bin/test-cgi.bat?|echo - which should return
# an HTTP 500 error containing the string 'ECHO is on'
# We just check for 'ECHO' (capitalized), as this should remain the same across
# most international versions of Windows(?)

include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");
if ( get_kb_item("Services/www/" + port + "/embedded") ) exit(0, "The web server listening on port "+port+" is embedded.");

banner = get_http_banner(port:port);
if (!banner) exit(1, "Failed to get the banner from the web server listening on port "+port+".");
if ("Server:" >!< banner) exit(0, "The banner from port " + port + " does not have a Server response header.");
if (ereg(string:banner, pattern:'Server:.*(Apache-Coyote|Tomcat)')) exit(0, "The web server listening on port " + port + " is Apache Tomcat, not Apache.");
if (ereg(pattern:"^Server:.*Apache", string:banner)) exit(0, "The web server listening on port " + port + " is not Apache.");

if (report_paranoia < 2)
{
  os = get_kb_item("Host/OS");
  if (isnull(os)) exit(0, "It was not possible to determine if the host is running Windows.");
  if ("Windows" >!< os) exit(0, "The host does not appear to be running Windows.");
}

soc = http_open_socket(port);
if (!soc) exit(1, "Failed to open a socket on port "+port+".");

url = "/cgi-bin/test-cgi.bat?|echo";
req = http_get(item:url, port:port);
send(socket:soc, data:req);
res = http_recv(socket:soc);
http_close_socket(soc);

if (ereg(pattern:"^HTTP/[0-9]\.[0-9] 500 ", string:res)) exit(0, "The web server listening on port "+port+" did not return a 500 response code as expected.");
if ("ECHO" >< res)
{
  if (report_verbosity > 0)
  {
    report = '\n' + "Nessus was able to execute the command 'ECHO' on the remote host using" +
             '\n' + 'the following URL :' +
             '\n' +
             '\n' + '  ' + build_url(port:port, qs:url) +
             '\n';
    if (report_verbosity > 1)
    {
      report += '\n' + 'This produced the following results :' +
                '\n' + 
                '\n' + res;
    }
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The web server listening on port "+port+" is not affected.");
