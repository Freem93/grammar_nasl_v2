#
# This script was written by Tor Houghton, but I looked at "htdig" by 
# Renaud Deraison <deraison@cvs.nessus.org>
#
# Changes by Tenable:
#	- pattern read is different (RD)
#	- request /SilverStream not /SilverStream/Pages (RD)
#       - revised plugin title (4/3/2009)
#       - Updated to use compat.inc (11/20/2009)
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added links to the Bugtraq message archive
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(10846);
 script_version ("$Revision: 1.16 $");
 script_osvdb_id(17113);
 script_cvs_date("$Date: 2016/11/03 21:08:35 $");


 script_name(english:"SilverStream Directory Listing");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The SilverStream application server running on the remote host
currenly has directory listings enabled.  An unauthenticated, remote
attacker may use this issue to gain more knowledge about the service
and possibly to retrieve sensitive files." );
 #https://web.archive.org/web/20011226154728/http://archives.neohapsis.com/archives/sf/pentest/2000-11/0147.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c550d49");
 script_set_attribute(attribute:"solution", value:
"Reconfigure the server to disable directory listings." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/02/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/11/14");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Checks if SilverStream directory listings are disabled.");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tor Houghton");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
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
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);

url = string("/SilverStream");
req = http_get(item:url, port:port);
rep = http_keepalive_send_recv(port:port, data:req);
if (isnull(rep)) exit(0);

lookfor = "<html><head><title>.*SilverStream.*</title>";
      
if((egrep(pattern:lookfor, string:rep)) && ("/Pages" >< rep))
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "The following request can be used to verify the issue :\n",
      "\n",
      "  ", build_url(port:port, qs:url), "\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
