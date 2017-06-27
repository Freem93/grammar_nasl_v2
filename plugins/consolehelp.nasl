#
# This script was written by John Lampe...j_lampe@bellsouth.net 
#
# Modifications by Tenable Network Security :
# -> Check for an existing .jsp file, instead of /default.jsp
# -> Expect a jsp signature
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(11724);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2015/09/24 21:08:38 $");

 script_cve_id("CVE-2000-0682");
 script_bugtraq_id(1518);
 script_osvdb_id(1481);
 
 script_name(english:"BEA WebLogic FileServlet Source Code Disclosure");
 script_summary(english:"Checks for WebLogic file disclosures ");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to an information disclosure attack." );
 script_set_attribute(attribute:"description", value:
"The version of the WebLogic web application installed on the remote
host contains a flaw such that by inserting a /ConsoleHelp/ into a
URL, critical source code files may be viewed." );
 script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technology/deploy/security/wls-security/12.html" );
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate Service Pack as described in the vendor advisory
referenced above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/07/31");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();
 
 script_category(ACT_GATHER_INFO); 
 
 script_copyright(english:"This script is Copyright (C) 2003-2015 John Lampe");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

jspfiles = get_kb_list(string("www/", port, "/content/extensions/jsp"));
if (isnull(jspfiles)) jspfiles = make_list("/default.jsp");
else jspfiles = make_list(jspfiles);

cnt = 0;

foreach file (jspfiles)
{ 
 if (file[0] != '/') file = '/' + file;
 url = "/ConsoleHelp" + file;
 req = http_get(item:url, port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

 if ( "<%" >< res && "%>" >< res )
 {
  # Unless we're paranoid, make sure we don't see the same thing in the original response.
  if (report_paranoia < 2)
  {
    req2 = http_get(item:file, port:port);
    res2 = http_keepalive_send_recv(port:port, data:req2);
    if (isnull(res2)) exit(1, "The web server on port "+port+" failed to respond.");
    if ("<%" >< res2 && "%>" >< res2) continue;
  }

  if (report_verbosity > 0)
  {
   report = 
    '\n' + "Nessus was able to retrieve the source of '" + file + "' by sending" +
    '\nthe following request :' +
    '\n' +
    '\n  ' + build_url(port:port, qs:url) + '\n';

   if (report_verbosity > 1)
    report += 
     '\nHere is the full response :' +
     '\n' +
     '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + 
     '\n' + res +
     crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';

   security_warning(port:port, extra:report);
  }
  else security_warning(port); 
  exit(0);
 }

 cnt ++;
 if(cnt > 10) break;
}
exit(0, "The web server on port "+port+" is not affected.\n");
