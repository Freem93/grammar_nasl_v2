#
# This script was written by David Kyger <david_kyger@symantec.com>
#
# See the Nessus Scripts License for details
#

include("compat.inc");

if(description)
{
  script_id(12085);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/09 20:31:00 $");

  script_name(english:"Apache Tomcat Servlet / JSP Container Default Files");
  script_summary(english:"Checks for Apache Tomcat default files.");
 
  script_set_attribute(attribute:"synopsis", value:"The remote web server contains example files.");
  script_set_attribute(attribute:"description", value:
"Example JSPs and Servlets are installed in the remote Apache Tomcat
servlet / JSP container. These files should be removed as they may
help an attacker uncover information about the remote Tomcat install
or host itself. The example files may also contain vulnerabilities
such as cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"solution", value:
"Review the files and delete those that are not needed.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/03/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 David Kyger");
  script_family(english:"Web Servers");

  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);
if (!port) exit(0);

if(get_port_state(port))
 {
  pat1 = "The Jakarta Project";
  pat2 = "Documentation Index";
  pat3 = "Examples with Code";
  pat4 = "Servlet API";
  pat5 = "Snoop Servlet";
  pat6 = "Servlet Name";
  pat7 = "JSP Request Method";
  pat8 = "Servlet path";
  pat9 = "session scoped beans";
  pat9 = "Java Server Pages";
  pat10 = "session scoped beans";
  

  fl[0] = "/tomcat-docs/index.html";
  fl[1] = "/examples/servlets/index.html";
  fl[2] = "/examples/servlet/SnoopServlet";
  fl[3] = "/examples/jsp/snp/snoop.jsp";
  fl[4] = "/examples/jsp/index.html";

  warning = "";
  for(i=0;fl[i];i=i+1) {
    req = http_get(item:fl[i], port:port);
    buf = http_keepalive_send_recv(port:port, data:req);
    if ( buf == NULL ) exit(0);
    if ((pat1 >< buf && pat2 >< buf) || (pat3 >< buf && pat4 >< buf) || (pat5 >< buf && pat6 >< buf) || (pat7 >< buf && pat8 >< buf) || (pat9 >< buf && pat10 >< buf)) {
     warning += string("\n  ", fl[i]);
     flag = 1;
     }
   }
    if (flag > 0) { 
     report = '\nThe following default files were found :\n'+warning+'\n';
     security_warning(port:port, extra:report);
     set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    }
}
