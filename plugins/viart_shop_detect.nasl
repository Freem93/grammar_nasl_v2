#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64292);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/01/30 12:16:53 $");

  script_name(english:"ViArt Shop Detection");
  script_summary(english:"Looks for ViArt Shop");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a shopping cart application written in
PHP."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts ViArt Shop, a shopping cart application
written in PHP."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.viart.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:viart:viart_shop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

if (thorough_tests) dirs = list_uniq(make_list("/shop", "/cart", "/viart", cgi_dirs()));
else dirs = make_list(cgi_dirs());

checks = make_array();

regexes = make_list();
regexes[0] = make_list('_Name>Viart', 'ViArt Shop PHP Shopping Cart<');
# viart_shop.xml does not appear to be regularly updated
# version information from this page may not be accurate
#regexes[1] = make_list('Program_Version>(.+)</Program_Version>');
checks["/viart_shop.xml"] = regexes;

installs = find_install(appname:"viart_shop", checks:checks, dirs:dirs, port:port);
if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, "ViArt Shop", port);

report = NULL;
if (report_verbosity > 0)
{
  report = get_install_report(
    display_name : 'ViArt Shop',
    installs     : installs,
    port         : port
  );
  security_note(port:port, extra:report);
}
else security_note(port);

