#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65058);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/02/11 00:06:37 $");

  script_name(english:"Foswiki Detection");
  script_summary(english:"Looks for Foswiki");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server contains a wiki system written in Perl."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running Foswiki, an open source wiki system written
in Perl."
  );
  script_set_attribute(attribute:"see_also", value:"http://foswiki.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foswiki:foswiki");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

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

port = get_http_port(default:80);

if (thorough_tests) dirs = list_uniq(make_list("/foswiki/bin", "/wiki/bin", "/cgi-bin/foswiki", cgi_dirs()));
else dirs = make_list(cgi_dirs());

checks = make_array();

regexes = make_list();
regexes[0] = make_list(
  'powered by Foswiki',
  '<h2><a name="System_Web_Utilities"'
);
regexes[1] = make_list(
  "version <strong>Foswiki-([0-9\.\-a-zA-Z]+)",
  "version <strong>v([0-9\.\-a-zA-Z]+)"
);
checks["/view/System/WebHome?rev=1"] = regexes;

installs = find_install(
  appname : "foswiki",
  checks  : checks,
  dirs    : dirs,
  port    : port,
  follow_redirect: 1
);

if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, "Foswiki", port);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'Foswiki',
    installs     : installs,
    port         : port,
    item         : "/view"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
