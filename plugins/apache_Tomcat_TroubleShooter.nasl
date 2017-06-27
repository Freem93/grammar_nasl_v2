#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(11046);
 script_version("$Revision: 1.36 $");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");

 script_cve_id("CVE-2002-2006");
 script_bugtraq_id(4575);
 script_osvdb_id(849);

 script_name(english:"Apache Tomcat TroubleShooter Servlet Information Disclosure");
 script_summary(english:"Tests whether the Apache Tomcat TroubleShooter Servlet is installed");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a path disclosure issue.");
 script_set_attribute(attribute:"description", value:
"The default installation of Apache Tomcat includes various sample JSP
pages and servlets.  One of these, the 'TroubleShooter' servlet,
discloses Tomcat's installation directory when accessed directly.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Apr/322");
 script_set_attribute(attribute:"solution", value:
"Example files should not be left on production servers.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/04/22");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/07/15");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:apache:tomcat");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002-2016 Matt Moore");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl","http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/tomcat");
 script_require_ports("Services/www", 80, 8080);
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if (!port) exit(0, "No web servers were found");
if(!get_port_state(port)) exit(0, "Port "+port+" is not open.");

banner = get_http_banner(port: port);
if (!banner) exit(1, "Failed to get the banner from the web server listening on port "+port+".");
if ("Tomcat" >!< banner && "Apache-Coyote" >!< banner)
  exit (0, "The web server listening on port "+port+" is not Tomcat.");

url = "/examples/servlet/TroubleShooter";
req = http_get(item:url, port:port);
r =   http_keepalive_send_recv(port:port, data:req);
confirmed = string("TroubleShooter Servlet Output"); 
confirmed_too = string("hiddenValue");
if ((confirmed >< r) && (confirmed_too >< r)) 	
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "The 'TroubleShooter' servlet is accessible as :\n",
      "\n",
      "  ", build_url(port:port, qs:url), "\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "The web server listening on port "+port+" is not affected.");
