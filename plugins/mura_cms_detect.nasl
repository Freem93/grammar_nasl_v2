#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49697);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"Mura CMS Detection");
  script_summary(english:"Looks for Mura's admin page");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts an open source content management
script (CMS) written in ColdFusion."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Mura CMS, an open source content management system written in
ColdFusion, is available through the remote web server."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.getmura.com/index.cfm");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
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
include("webapp_func.inc");


port = get_http_port(default:80, embedded:FALSE);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/mura", "/muracms", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  url = dir + '/';
  res = http_send_recv3(
    method          : "GET",
    port            : port,
    item            : url,
    follow_redirect : 2,
    exit_on_fail    : TRUE
  );

  if (
    'meta name="generator" content="Mura CMS' >< res[2] ||
    '/includes/themes/merced/css/typography.css' >< res[2] ||
    'DD_roundies.addRule' >< res[2]
  )
  {
    version = NULL;

    # nb: the version in the generator meta tag isn't necessarily granular.
    pat = 'meta name="generator" content="Mura CMS ([0-9]+\\.[^"]+)"';
    matches = egrep(pattern:pat, string:res[2]);
    if (matches)
    {
      foreach match (split(matches, keep:FALSE))
      {
        item = eregmatch(pattern:pat, string:match);
        if (!isnull(item))
        {
          version = item[1];
          break;
        }
      }
    }

    installs = add_install(
      appname  : "mura_cms",
      installs : installs,
      port     : port,
      dir      : dir,
      ver      : version
    );

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}
if (isnull(installs))
  exit(0, "Mura CMS was not detected on the web server on port "+port+".");


# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    display_name : "Mura CMS"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
