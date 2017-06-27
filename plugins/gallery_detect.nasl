#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65766);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/02/10 23:56:41 $");

  script_name(english:"Gallery Detection");
  script_summary(english:"Looks for Gallery");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a photo album application written in
PHP."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running Gallery, an open source photo album
application written in PHP."
  );
  script_set_attribute(attribute:"see_also", value:"http://galleryproject.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gallery_project:gallery");
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

port = get_http_port(default:80, php:TRUE);

if (thorough_tests) dirs = list_uniq(make_list("/gallery", cgi_dirs()));
else dirs = make_list(cgi_dirs());

checks = make_array();

regexes = make_list();
regexes[0] = make_list(
  'Gallery (.+)("|\\>|\\<)',
  'g(allery\\.|-|s)?(f|F)ooter',
  'href=(")?http://gallery(project\\.org|\\.sourceforge\\.net|\\.menalto\\.com)'
);
regexes[1] = make_list(
  # Versions 1.x
  "\>Gallery\<\/a\> v(1[0-9\.\-a-zA-Z]+)",
  "\>Gallery v(.+)\<\/a\>",
  "\<!-- (1[0-9\.\-a-zA-Z ]+) --\>",
  # Versions 3.x
  "\>Gallery ([0-9\.\-a-zA-Z ]+)"
);
checks["/index.php"] = regexes;

# Versions 2.x.  Index page does not contain full version
regexes = make_list();
regexes[0] = make_list('@package GalleryCore');
regexes[1] = make_list("\>setGalleryVersion\('(.+)'\)");
checks["/modules/core/module.inc"] = regexes;

installs = find_install(
  appname : "gallery",
  checks  : checks,
  dirs    : dirs,
  port    : port,
  follow_redirect : 1
);

if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, "Gallery", port);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'Gallery',
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
