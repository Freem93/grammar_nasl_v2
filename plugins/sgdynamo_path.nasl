#
# This script written by Scott Shebby (12/2003) 
#

# See the Nessus Scripts License for details
#
# Ref:
# From: "Ruso, Anthony" <aruso@positron.qc.ca>
# To: Penetration Testers <PEN-TEST@SECURITYFOCUS.COM>
# Subject: Sgdynamo.exe Script -- Path Disclosure
# Date: Wed, 16 May 2001 11:55:32 -0400
#
# Changes by Tenable:
#	- Description  [RD]
#	- Support for multiple CGI directories  [RD]
#	- HTTP KeepAlive support  [RD]
#	- egrep() instead of eregmatch()  [RD]
#       - updated title (4/29/09)
#       - Updated to use compat.inc, added CVSS score (11/20/2009)


include("compat.inc");

if (description)
{
 script_id(11954);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2015/10/21 20:34:21 $");

 script_osvdb_id(54010);

 script_name(english:"SGDynamo sgdynamo.exe HTNAME Parameter Path Disclosure");
 script_summary(english:"sgdynamo.exe Path Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server has a CGI script that is affected by an
information disclosure vulnerability.");
 script_set_attribute(attribute:"description", value:
"The CGI 'sgdynamo.exe' can be tricked into giving the physical path
to the remote web root. 

This information may be useful to an attacker who can use it to launch
more effective attacks against the remote server.");
 script_set_attribute(attribute:"solution", value:"Unknown at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/12/18");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2015 Scott Shebby");
 script_family(english:"CGI abuses");

 script_dependencie("iis_detailed_error.nasl", "404_path_disclosure.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (get_kb_item("www/"+port+"/iis_detailed_errors"))  exit(0, "The web server listening on port "+port+" appears to be an instance of IIS that returns detailed error messages.");
if (get_kb_item("www/"+port+"/generic_path_disclosure"))  exit(0, "The web server listening on port "+port+" is known to be affected by a generic path disclosure vulnerability.");

pat = "[^A-Za-z]([A-Za-z]:[/\\]sgdynamo\.exe|[A-Za-z]:[/\\][^:<>|\*?]*[/\\]sgdynamo\.exe)";
foreach dir (cgi_dirs())
{
 url = dir + "/sgdynamo.exe?HTNAME=sgdynamo.exe";
 req = http_get(item:url, port:port);
 resp = http_keepalive_send_recv(port:port, data:req);
 if (isnull(resp)) exit(0, "The web server listening on port "+port+" failed to respond.");

 matches = egrep(pattern:pat, string:resp);
 if (matches)
 {
   path = NULL;
   foreach match (split(matches, keep:FALSE))
   {
     item = eregmatch(pattern:pat, string:match);
     if (!isnull(item))
     {
       path = item[1];
       break;
     }
   }
   if (isnull(path)) exit(1, "Failed to extract the disclosed path from the web server listening on port "+port+".");

   if (report_verbosity > 0)
   {
     report = 
       '\n  URL            : ' + build_url(qs:url, port:port) +
       '\n  Path disclosed : ' + path + 
       '\n';
     security_warning(port:port, extra:report); 
   } 
   else security_warning(port);
   exit(0);
 }
}
exit(0, "The web server listening on port "+port+" is not affected.");
