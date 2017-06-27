#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39500);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/13 15:19:34 $");

  script_name(english:"Zen Cart Detection");
  script_summary(english:"Looks for traces of Zen Cart");

  script_set_attribute(attribute:"synopsis", value:"The remote web server contains a shopping cart system written in PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Zen Cart, an open source shopping cart
application written in PHP.");
  script_set_attribute(attribute:"see_also", value:"http://www.zen-cart.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zen-cart:zen_cart");
  script_end_attributes();

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("install_func.inc");


port = get_http_port(default:80, embedded: 0, php: 1);

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/zencart", "/zen-cart", "/cart", "/catalog", "/store", "/shop", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = make_array();
foreach dir (dirs)
{
  # Grab index.php.
  res = http_get_cache(item:string(dir, "/"), port:port, exit_on_fail: 1);

  # If it's Zen Cart...
  if (
    'author" content="The Zen Cart&trade; Team' >< res ||
    'generator" content="shopping cart program by Zen Cart&trade;' >< res ||
    'alt="Powered by Zen Cart :: The Art of E-Commerce"' >< res ||
    (
      '<!--bof-branding display-->' >< res &&
      '<!--bof-header ezpage links-->' >< res &&
      '?main_page=advanced_search_result" method="get"' >< res
    ) ||
    '</a>. Powered by <a href="http://www.zen-cart.com"' >< res
  )
  {
    version = NULL;

    # nb: there's no good way to search for the version.

    # If still unknown, just mark it as "unknown".
    if (isnull(version)) version = "unknown";

    if (dir == "") dir = "/";
    set_kb_item(
      name:string("www/", port, "/zencart"),
      value:string(version, " under ", dir)
    );
    set_kb_item(name:"www/zencart", value:TRUE);
    if (installs[version]) installs[version] += ';' + dir;
    else installs[version] = dir;

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}


# Report findings.
if (max_index(keys(installs)))
{
  if (report_verbosity > 0)
  {
    info = "";
    n = 0;
    foreach version (sort(keys(installs)))
    {
      info += '  Version : ' + version + '\n';
      foreach dir (sort(split(installs[version], sep:";", keep:FALSE)))
      {
        if (dir == '/') url = dir;
        else url = dir + '/';

        register_install(
          app_name:"Zen Cart",
          path:url,
          version:version,
          port:port,
          cpe:"cpe:/a:zen-cart:zen_cart");

        info += '  URL     : ' + build_url(port:port, qs:url) + '\n';
        n++;
      }
      info += '\n';
    }

    report = '\nThe following instance';
    if (n == 1) report += ' of Zen Cart was';
    else report += 's of Zen Cart were';
    report += ' detected on the remote host :\n\n' + info;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
