#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(69368);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/03 20:48:27 $");

  script_name(english:"BigTree CMS Detection");
  script_summary(english:"Looks for evidence of BigTree CMS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a content management system written in
PHP."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts BigTree CMS, an open source content
management system using PHP and MySQL."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.bigtreecms.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bigtreecms:bigtree_cms");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php:TRUE);

app = "BigTree CMS";

if (thorough_tests) dirs = list_uniq(make_list("/bigtree", "/bigtree/site", "/site", cgi_dirs()));
else dirs = make_list(cgi_dirs());


checks = make_array();

regexes = make_list();
regexes[0] = make_list(
  # version 4
  '&nbsp;&copy; .+ <a href="http://www.fastspot.com" target="_blank"> Fastspot</a>',

  '<div class="footer_logo logo_bigtree">',
  '<title>BigTree CMS - Admin</title>'
);
regexes[1] = make_list(
  # version 4
  'Version ([^&]+)&(copy|nbsp);.+<a href="http://www.fastspot.com" target="_blank"> Fastspot</a>'

  # nb: for version 3.x, the version appears in admin/images/big_tree_logo.jpg.
);
checks["/admin/login/"] = regexes;
checks["/index.php/admin/login/"] = regexes;

installs = find_install(
  appname : "bigtree_cms",
  checks  : checks,
  all     : FALSE,
  dirs    : dirs,
  port    : port
);

if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, app, port);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : app,
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
