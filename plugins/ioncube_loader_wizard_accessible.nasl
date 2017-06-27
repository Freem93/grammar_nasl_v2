#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73330);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/11/23 20:31:32 $");

  script_name(english:"ionCube loader-wizard.php Accessible");
  script_summary(english:"Looks for ionCube Loader Wizard script");

  script_set_attribute(attribute:"synopsis", value:"A setup wizard is accessible on the remote web server.");
  script_set_attribute(attribute:"description", value:
"ionCube, an encoding and PHP file security tool written in PHP, is
running on the remote host. The 'loader-wizard.php' script that
contains setup and configuration assistance and provides access to
sensitive information about the web server is accessible to remote,
unauthenticated users.");
  script_set_attribute(attribute:"see_also", value:"http://www.ioncube.com/loaders.php");
  script_set_attribute(attribute:"solution", value:"Remove access to 'loader-wizard.php' or remove the script.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");


  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ioncube:php_encoder");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

dirs = make_list(cgi_dirs());
urls = make_list();
path = "/loader-wizard.php?page=default";

foreach dir (dirs)
{
  res = http_send_recv3(
    method : "GET",
    item   : dir + path,
    port   : port,
    exit_on_fail : TRUE
  );
  if ('<title>ionCube Loader Wizard</title>' >< res[2] &&
     'Wizard version' >< res[2]
  )
  { # Grab version to store in KB
    version = UNKNOWN_VER;
    match = eregmatch(pattern:"Loader Wizard version ([0-9\.]+) \s", string:res[2]);
    if (!isnull(match)) version = match[1];

    urls = make_list(urls, dir + "/loader-wizard.php");
    set_kb_item(name:"www/" +port+ "/ioncube", value:version + ' under ' + dir);
    set_kb_item(name:"www/ioncube", value:TRUE);
  }
}

if (max_index(urls) == 0) audit(AUDIT_WEB_APP_NOT_INST, "ionCube loader-wizard.php", port);

if (report_verbosity > 0)
{
  report = get_vuln_report(
    items : urls,
    port  : port
  );
  security_warning(port:port, extra:report);
}
else security_warning(port);
