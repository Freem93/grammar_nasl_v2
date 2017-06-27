# Written by Gareth Phillips - SensePost PTY ltd
# www.sensepost.com
#

# Changes by Tenable:
# - Revised plugin title (4/7/2009)
# - Updated to use compat.inc (11/20/2009)


include("compat.inc");

if (description) {
script_id(22867);
script_version("$Revision: 1.10 $");
script_cvs_date("$Date: 2011/03/17 01:57:39 $"); 

script_name(english:"Web Site sitemap.xml File and Directory Disclosure");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a 'sitemap.xml' file." );
 script_set_attribute(attribute:"description", value:
"The Sitemap Protocol allows you to inform search engines about URLs on
a website that are available for crawling.  In its simplest form, a
Sitemap is an XML file that lists URLs for a site.

It has been discovered that many site owners are not building their
Sitemaps through spidering, but by scripted runs on their web root
directory structures.  If this is the case, an attacker may be able to
use sitemaps to enumerate all files and directories in the web server
root." );
 script_set_attribute(attribute:"see_also", value:"http://www.quietmove.com/blog/google-sitemap-directory-enumeration-0day/" );
 script_set_attribute(attribute:"see_also", value:"https://www.google.com/webmasters/sitemaps/docs/en/protocol.html" );
 script_set_attribute(attribute:"solution", value:
"Site owners should be wary of automatically generating sitemap.xml
files, and admins should review the contents of there sitemap.xml file
for sensitive material." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/10/14");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


script_summary(english:"Checks for a web server's sitemap.xml");

script_category(ACT_GATHER_INFO);
script_family(english:"CGI abuses");

script_copyright(english:"This script is Copyright (C) 2006-2011 SensePost");

script_dependencie("http_version.nasl");
script_require_ports("Services/www", 80);

exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

if (thorough_tests)
  dirs = get_kb_list(string("www/", port, "/content/directories"));
if(isnull(dirs))dirs = make_list("", "/sitemap", "/map"); # Just some Defaults
dirs = list_uniq(make_list(dirs, cgi_dirs()));

info = '';
n = 0;
foreach d (dirs)
{
  # Trying to retrieve the file.
  url = d+"/sitemap.xml";
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  if ("?xml version" >< res)
  {
    pat = "<loc>(.+)</loc>";
    matches = egrep(string:res, pattern:pat);
    if (matches)
    {
      n++;
      if (report_verbosity) info += '\n' + '  ' + url + '\n';

      if (report_verbosity > 1)
      {
        foreach match (split(matches))
        {
          match = chomp(match);
          loc = eregmatch(pattern:pat, string:match);
          if (!isnull(loc)) 
            info += '    <loc>' + loc[1] + '</loc>\n';
        }
      }
    }
  }
  if (info && !thorough_tests) break;
}



if (n)
{
  if (info)
  {
    report = string(
      "\n",
      "Nessus gathered the following information from Sitemaps :\n",
      info
    );
  }
  else security_note(port:port,extra:report);
}
