#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Script audit and contributions from Carmichael Security 
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB refs (4/9/2009)


include("compat.inc");

if(description)
{
 script_id(11037);
 script_version("$Revision: 1.23 $");
 script_cve_id("CVE-2002-1855", "CVE-2002-1856", "CVE-2002-1857", "CVE-2002-1858", 
               "CVE-2002-1859", "CVE-2002-1860", "CVE-2002-1861");
 script_bugtraq_id(5119);
 script_osvdb_id(44525, 53449, 53450, 53451, 53452, 53453, 53454);

 script_name(english:"Multiple Server Crafted Request WEB-INF Directory Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"By making a specially-formatted request to the remote web server, it
is possible to retrieve files located under the 'WEB-INF' directory. 

Note that this vulnerability is known to affect the Win32 versions of
multiple J2EE servlet containers / application servers." );
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for a patch." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/07/01");
 script_cvs_date("$Date: 2015/09/24 21:08:39 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 
 script_summary(english:"Tests for WEB-INF folder access");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002-2015 Matt Moore");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(get_port_state(port))
{
 url = "/WEB-INF./web.xml";
 req = http_get(item:url, port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if ( ! r ) exit(0);
 confirmed = string("web-app"); 
 confirmed_too = string("?xml");
 if ((confirmed >< r) && (confirmed_too >< r))
 {
  if (report_verbosity)
  {
   report = string(
    "\n",
    "Nessus was able to retrieve the contents of 'web.xml' using the\n",
    "following URL :\n",
    "\n",
    "  ", build_url(port:port, qs:url), "\n"
   );
   if (report_verbosity > 1)
   {
    report = string(
     report,
     "\n",
     "Here is the information extracted :\n",
     "\n",
     r
    );
   }
   security_warning(port:port, extra:report);
  }
  else security_warning(port);
 }
}
