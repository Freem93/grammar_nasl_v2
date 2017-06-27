#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45488);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/10/18 20:50:30 $");

  script_name(english:"AjaXplorer Detection");
  script_summary(english:"Looks for the AjaXplorer credits page");

  script_set_attribute(
    attribute:"synopsis",
    value:"A file management application is running on the remote web server."
  );
  script_set_attribute(
    attribute:"description",
    value:
"AjaXplorer, a PHP application for managing files on a web server, is
hosted on the remote web server."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.ajaxplorer.info/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ajaxplorer:ajaxplorer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
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

installs = NULL;
files_and_patterns = make_array(
  '/content.php?get_action=display_doc&doc_file=CREDITS', '<body>AjaXplorer Version ([0-9.]+)',
  '/index.php?get_action=get_boot_conf', '"ajxpVersion":"([0-9.]+)"'
);

if (thorough_tests) dirs = list_uniq(make_list("/ajaxplorer", cgi_dirs()));
else dirs = cgi_dirs();

foreach dir (dirs)
{
  foreach file (keys(files_and_patterns))
  {
    url = dir + file;

    res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

    match = eregmatch(string:res[2], pattern:files_and_patterns[file], icase:TRUE);
    if (match)
    {
      installs = add_install(
        installs:installs,
        dir:dir,
        ver:match[1],
        appname:'ajaxplorer',
        port:port
      );

      if (!thorough_tests) break;
    }
  }
}

if (isnull(installs))
   audit(AUDIT_WEB_APP_NOT_INST, 'AjaXplorer', port);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'AjaXplorer',
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);
