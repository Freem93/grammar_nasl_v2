#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#      Also covers BugtraqID: 5194 (same Advisory ID#: wp-02-0008)
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(11041);
 script_version("$Revision: 1.35 $");
 script_cvs_date("$Date: 2016/11/11 19:58:29 $");

 script_cve_id("CVE-2002-0682");
 script_bugtraq_id(5193);
 script_osvdb_id(4973);
 
 script_name(english:"Apache Tomcat /servlet Mapping XSS");
 script_summary(english:"Tests for Apache Tomcat /servlet XSS Bug");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting issue.");
 script_set_attribute(attribute:"description", value:
"Apache Tomcat is the servlet container that is used in the official
Reference Implementation for the Java Servlet and JavaServer Pages
technologies. 

By using the /servlet/ mapping to invoke various servlets / classes it
is possible to cause Tomcat to throw an exception, allowing XSS
attacks.");
 script_set_attribute(attribute:"solution", value:
"The 'invoker' servlet (mapped to /servlet/), which executes anonymous
servlet classes that have not been defined in a web.xml file should be
unmapped. 

The entry for this can be found in the
/tomcat-install-dir/conf/web.xml file.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
 script_set_attribute(attribute:"see_also", value:"http://www.westpoint.ltd.uk/advisories/wp-02-0008.txt");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/07/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/07/10");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002-2016 Matt Moore");
 script_family(english:"CGI abuses : XSS");

 script_dependencie("find_service1.nasl", "http_version.nasl", "cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/tomcat");
 script_require_ports("Services/www", 8080);
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);
if (!port) exit(0, "No web servers were found.");

if(!get_port_state(port)) exit(0, "Port "+port+" is not open.");
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0, "The web server listening on port "+port+" is affected by a generic XSS vulnerability.");

banner = get_http_banner(port:port);
if (!banner) exit(1, "Failed to get the banner from the web server listening on port "+port+".");
if ("Tomcat" >!< banner && "Apache-Coyote" >!< banner)
  exit (0, "The web server listening on port "+port+" is not Tomcat.");


req = http_get(item:"/servlet/org.apache.catalina.ContainerServlet/<SCRIPT>alert(document.domain)</SCRIPT>", port:port);
r = http_keepalive_send_recv(port:port, data:req);
confirmed = string("<SCRIPT>alert(document.domain)</SCRIPT>"); 
confirmed_too = string("javax.servlet.ServletException");
  if ((confirmed >< r) && (confirmed_too >< r)) {
		security_warning(port);
		set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
else exit(0, "The web server listening on port "+port+" is not affected.");
