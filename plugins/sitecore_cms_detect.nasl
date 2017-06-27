#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55978);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/08 22:04:50 $");

  script_name(english:"Sitecore CMS Detection");
  script_summary(english:"Looks for the Sitecore CMS login page");

  script_set_attribute(
    attribute:"synopsis",
    value:"A web-based content management application was detected on the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Sitecore CMS, a web-based content management system, was detected on
the remote host."
  );

  # http://www.sitecore.net/Products/Web-Content-Management/Content-Management.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d74468d6");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sitecore:cms");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ASP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, asp:TRUE);
dirs = make_list('/sitecore', cgi_dirs());
installs = NULL;

foreach dir (dirs)
{
  version = NULL;
  revision = NULL;

  # Try login page first
  url = dir + '/login/default.aspx';
  res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);
  if (
    (
      '<div id="LoginTitle">Welcome to Sitecore' >< res[2] ||
      ('<div id="LoginTitle">' >< res[2] && 'Welcome to Sitecore' >< res[2])
    )
    &&
    'Sitecore.NET' >< res[2]
  )
  {
    pat = 'Sitecore.NET ([0-9.]+) \\(rev\\. ([0-9]+) (Hotfix [0-9-]+)?\\)';
    matches = egrep(pattern:pat, string:res[2]);

    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          version = item[1];
          revision = item[2];
          if (!isnull(item[3]))
            revision += ' ' + item[3];
        }
      }
    }
  }

  if (isnull(version) && isnull(revision))
  {
    # Try sitecore.version.xml
    url = dir + '/shell/sitecore.version.xml';
    res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

    if ("<company>Sitecore Corporation</company>" >< res[2])
    {
      major = substr(res[2], stridx(res[2], "<major>"), stridx(res[2], "</major>")-1) - "<major>";
      minor = substr(res[2], stridx(res[2], "<minor>"), stridx(res[2], "</minor>")-1) - "<minor>";
      build = substr(res[2], stridx(res[2], "<build>"), stridx(res[2], "</build>")-1) - "<build>";
      revision = substr(res[2], stridx(res[2], "<revision>"), stridx(res[2], "</revision>")-1) - "<revision>";

      version = major + '.' + minor + '.' + build;
    }
  }

  # Note that if a hotfix ID is present,
  # it remains as part of the version
  # string as seen on a Sitecore login page.
  if (version && revision)
  {
    installs = add_install(
      installs : installs,
      dir      : dir,
      ver      : version + ' rev. ' + revision,
      appname  : 'sitecore_cms',
      port     : port
    );

    if (!thorough_tests) break;
  }
}

if (!isnull(installs))
{
  if (report_verbosity > 0)
  {
    report = get_install_report(display_name:"Sitecore CMS", installs:installs, port:port);
    security_note(port:port, extra:report);
  }
  else security_note(port:port);
}
else exit(0, 'Sitecore CMS was not detected on ' + port);
