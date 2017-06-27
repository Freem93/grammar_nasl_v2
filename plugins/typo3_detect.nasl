#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44117);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/09/30 14:12:37 $");

  script_name(english:"TYPO3 Detection");
  script_summary(english:"Searches for the TYPO3 login page.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a content management system written in
PHP.");
  script_set_attribute(attribute:"description", value:
"The remote host is running TYPO3, an open source content management
system written in PHP.");
  script_set_attribute(attribute:"see_also", value:"http://typo3.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:typo3:typo3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

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
include("install_func.inc");

port = get_http_port(default:80, php: TRUE);

installs = 0;
app = "TYPO3";
dirs = cgi_dirs();

if (thorough_tests)
{
  dirs = make_list(dirs, '/cms', '/site', '/typo3');
  dirs = list_uniq(dirs);
}

pat = '<meta name="generator" content="TYPO3 ([0-9\\.]+)';
foreach dir (dirs)
{
  pack_ver = NULL;
  version = NULL;

  url = dir + '/typo3/index.php';
  res = http_send_recv3(
    method : "GET",
    item   : url,
    port   : port,
    exit_on_fail : TRUE
  );

  if (
   ereg(pattern:'<title>TYPO3( CMS)? Login', string:res[2],multiline:TRUE) ||
   ereg(pattern:pat, string:res[2], multiline:TRUE)
  )
  {
    match = eregmatch(pattern:pat, string:res[2]);
    if (!empty_or_null(match[1])) pack_ver = match[1];
    else pack_ver = UNKNOWN_VER;

    # Attempt to access ChangeLog to grab the version
    res2 = http_send_recv3(
      method : "GET",
      port   : port,
      item   : dir + '/typo3_src/ChangeLog',
      exit_on_fail : TRUE
    );

    match = eregmatch(
     pattern : 'Release of TYPO3 ([0-9]+\\.[^\\(\\n]+)',
     string  : res2[2]
   );

   if (!empty_or_null(match[1])) version = match[1];
   else version = UNKNOWN_VER;

    installs++;

    register_install(
      app_name : app,
      path     : dir,
      rep_path : "/typo3/index.php",
      port     : port,
      version  : version,
      cpe      : "cpe:/a:typo3:typo3",
      webapp   : TRUE,
      extra    : make_array("Release Branch", pack_ver)
    );

    if (!thorough_tests) break;
  }
}

if (installs == 0) audit(AUDIT_WEB_APP_NOT_INST, app, port);

report_installs(port:port);
