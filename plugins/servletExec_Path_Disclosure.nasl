#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CAN
#
# See the Nessus Scripts License for details
#
# Changes by Tenable
# - Updated to use compat.inc (11/20/2009)



include("compat.inc");

if(description)
{
 script_id(10960);
 script_version ("$Revision: 1.19 $");
 script_cvs_date("$Date: 2016/05/13 15:33:30 $");

 script_cve_id("CVE-2002-0892");
 script_bugtraq_id(4793);
 script_osvdb_id(784);

 script_name(english:"ServletExec 4.1 ISAPI com.newatlanta.servletexec.JSP10Servlet Path Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure issue." );
 script_set_attribute(attribute:"description", value:
"By requesting a nonexistent .JSP file, or by invoking the JSPServlet
directly and supplying no filename, it is possible to make the
ServletExec ISAPI filter disclose the physical path of the webroot." );
 script_set_attribute(attribute:"see_also", value:"http://www.westpoint.ltd.uk/advisories/wp-02-0006.txt" );
 script_set_attribute(attribute:"solution", value:
"Use the main ServletExec Admin UI to set a global error page for the
entire ServletExec Virtual Server." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/05/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/05/22");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Tests for ServletExec 4.1 ISAPI Path Disclosure");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002-2016 Matt Moore");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{ 
 req = http_get(item:"/servlet/com.newatlanta.servletexec.JSP10Servlet", port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 confirmed = string("newatlanta");
 confirmedtoo = string("(filename = "); 
 if ((confirmed >< r) && (confirmedtoo ><r))	
 	security_warning(port);

}

