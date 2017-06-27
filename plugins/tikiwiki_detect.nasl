#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46736);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_name(english:"TikiWiki Detection");
  script_summary(english:"Looks for traces of TikiWiki");

  script_set_attribute(attribute:"synopsis",value:
"The remote web server hosts a PHP-based content management
application.");
  script_set_attribute(attribute:"description",value:
"The remote web server hosts TikiWiki (aka Tiki), a PHP-based content
management software used to build and maintain websites.");
  script_set_attribute(attribute:"see_also", value:"http://info.tiki.org/tiki-index.php");
  script_set_attribute(attribute:"solution",value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date",value:"2010/05/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tikiwiki:tikiwiki");
  script_end_attributes();

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

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

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/tikiwiki", "/tiki", cgi_dirs()));
else dirs = make_list(cgi_dirs());

installs = NULL;
page =  "/tiki-index.php";

foreach dir (dirs)
{
  # Grab the initial page.
  url = dir + page;
  res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

  # If it looks like tikiwiki.
  if (
    ('This is TikiWiki ' >< res[2] && 'alt="Powered by TikiWiki"' >< res[2]) ||
    (egrep(pattern:'Powered by <a href="http://info.(tikiwiki|tiki).org"', string:res[2]) && '>TikiWiki CMS/Groupware<' >< res[2]) ||
    (egrep(pattern:'Powered by <a target="_blank" href="http://(tikiwiki|tiki).org"', string:res[2]) && 'title="This is TikiWiki CMS/Groupware' >< res[2]) ||
     egrep(pattern:'name="generator" content="Tiki *Wiki CMS[ /]Groupware - http://(TikiWiki.org|tiki.org)"',string:res[2])
  )
  {
    version = UNKNOWN_VER;
    matches = egrep(pattern:"This is TikiWiki *(CMS/Groupware)? *v?([0-9]+(\.[0-9]+)*)", string:res[2]);
    if (matches)
    {
      foreach match (split(matches, sep:" ", keep:FALSE))
      {
        item = eregmatch(pattern:"^(v)?([0-9]+(\.[0-9]+)*($|(RC|rc|Beta|Alpha)[0-9]*))", string:match);

        if (!isnull(item))
        {
          version = item[2];
        }
      }
      if (version !~ "^[0-9]+(\.[0-9]+)*($|[^0-9])") version = UNKNOWN_VER;
    }

    installs = add_install(
      appname  : "tikiwiki",
      installs : installs,
      port     : port,
      dir      : dir,
      ver     : version
    );

    # Scan for multiple installations only if the "Perform thorough tests" setting is checked.
    if (!thorough_tests) break;
  }
}
if (isnull(installs)) audit(AUDIT_WEB_APP_NOT_INST, "TikiWiki", port);

# Report findings.
if (report_verbosity > 0)
{
  report = get_install_report(
    port         : port,
    installs     : installs,
    display_name : "TikiWiki",
    item         : page
  );
  security_note(port:port, extra:report);
}
else security_note(port);
