#
# This script was written by Tor Houghton, but I looked at "htdig" by 
# Renaud Deraison <deraison@cvs.nessus.org>
#
# Changes by rd:
# - phrasing in the report
# - pattern read
# Changes by Tenable
# - Updated to use compat.inc (11/20/2009)
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added link to the Bugtraq message archive
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(10847);
 script_version ("$Revision: 1.17 $");
 script_cvs_date("$Date: 2016/11/03 21:08:35 $");

 script_name(english:"SilverStream Database Structure Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"An unauthenticated, remote attacker can discover the internal structure
of the remote SilverStream database by sending a special request." );
 #https://web.archive.org/web/20011226154728/http://archives.neohapsis.com/archives/sf/pentest/2000-11/0147.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c550d49");
 script_set_attribute(attribute:"solution", value:
"Reconfigure the server so that others cannot view the database
structure." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/02/06");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_summary(english:"Checks if SilverStream database structure is visible");
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tor Houghton");
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
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);

url = string("/SilverStream/Meta/Tables/?access-mode=text");
req = http_get(item:url, port:port);
rep = http_keepalive_send_recv(port:port, data:req);
if (!isnull(rep))
{
  if("_DBProduct" >< rep)
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
}

