#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20129);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/05/13 21:05:51 $");

  script_name(english:"e107 Detection");
  script_summary(english:"Checks for the presence of e107");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a content management system (CMS)
written in PHP."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running e107, a content management system written
in PHP and with a MySQL back-end."
  );
  script_set_attribute(attribute:"see_also", value:"http://e107.org/");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/02");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:e107:e107");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:80, php:TRUE, embedded:FALSE);

# Search for e107.
if (thorough_tests) dirs = list_uniq(make_list("/e107", "/cms", cgi_dirs()));
else dirs = make_list(cgi_dirs());

checks = make_array();
installs = NULL;

regexes = make_list();
regexes[0] = make_list(
  'This site is powered by \\<a href="http://e107\\.org/" rel="external"\\>e107|e107_files/e107\\.css|e107 powered website\\.\\<br',
  "<input [^>]*name='(user|auth)(name|pass)'"
);
checks["/e107_admin/admin.php"] = regexes;

# Versions 0.5x
regexes = make_list();
regexes[0] = make_list(
  "e107 powered website\.\<br",
  'name="authsubmit" value="Log In"'
);
checks["/admin/admin.php"] = regexes;

installs = find_install(
  appname : 'e107',
  checks  : checks,
  dirs    : dirs,
  port    : port
);

if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, "e107", port);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'e107',
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
