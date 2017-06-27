#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66325);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/05/06 13:51:55 $");

  script_cve_id("CVE-2013-3055");
  script_bugtraq_id(59513);
  script_osvdb_id(92716);

  script_name(english:"Groovy Shell Unauthenticated Remote Command Execution");
  script_summary(english:"Checks for unprotected Groovy Shell");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an unprotected shell listening that allows for
remote command execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has an unprotected Groovy Shell bound to a TCP port
that is listening and allows for commands to be executed by an
unauthenticated, remote attacker.  This shell is known to be included
with Lexmark Markvision."
  );
  script_set_attribute(attribute:"see_also", value:"http://groovy.codehaus.org/Groovy+Shell");
  # http://support.lexmark.com/index?page=content&id=TE530&locale=en&userlocale=EN_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db169a54");
  script_set_attribute(
    attribute:"solution",
    value:
"Disable or restrict access to the shell.  If running Lexmark
Markvision, upgrade to version 1.8.0 or higher."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:codehaus:groovy");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/groovy_shell", 9789);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");
include("telnet2_func.inc");

global_var rcvdata, n, commands, command_index, port, groovy_detected;

groovy_detected = FALSE;

os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os)
  {
    commands = make_array(
      "ipconfig", "Windows IP Configuration"
    );
  }
  else
  {
    commands = make_array(
      "id", "uid=",
      "ifconfig", "inet"
    );
  }
}
else
{
  commands = make_array(
    "ipconfig", "Windows IP Configuration",
    "ifconfig", "inet",
    "id", "uid="
  );
}

n = 0;
command_index = 0;

appname = "Groovy Shell";

function telnet_callback()
{
  local_var substring, data, report, start, end, command, command_res, command_keys;

  data = _FCT_ANON_ARGS[0];
  if (isnull(data)) return;

  if (command_index >= max_index(keys(commands)))
    return;

  command_keys = keys(commands);
  command = command_keys[command_index];
  substring = commands[command];

  if (data[0] != '\0') rcvdata += data[0];

  if (n == 0)
  {
    if ("groovy> " >< rcvdata && "Groovy Shell" ><rcvdata)
    {
      groovy_detected = TRUE;
      telnet_write('println "' + command + '".execute().text\n');
      n = 1;
      rcvdata = '';
    }
  }
  else if (n == 1)
  {
    if ("groovy> " >< rcvdata)
    {
      telnet_write('go\n');
      n = 2;
      rcvdata = '';
    }
  }
  else if (n == 2)
  {
    if ("groovy> " >< rcvdata)
    {
      if (substring >< rcvdata && 'go' >< rcvdata && '===>' >< rcvdata)
      {
        start = stridx(rcvdata, 'go');
        end = stridx(rcvdata, '===>');

        command_res = substr(rcvdata, start + 2, end - 1);

        if (report_verbosity > 0)
        {
          report = '\nNessus was able to execute the "' + command +
                   '" and got the' +
                   '\nfollowing results : \n' + chomp(command_res) + '\n';
          security_hole(extra:report, port:port);
        }
        else security_hole(port);
        exit(0);
      }
      else
      {
        n = 1;
        rcvdata = '';
        command_index++;
        command = command_keys[command_index];
        telnet_write('println "' + command + '".execute().text\n');
      }
    }
  }
}

port = NULL;

port = get_service(svc:"groovy_shell", default:9789, exit_on_fail:TRUE);

if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

if (! telnet2_init(port: port, timeout: 3 * get_read_timeout()))
  audit(AUDIT_SOCK_FAIL, port);

telnet_loop();

if (groovy_detected)
  audit(AUDIT_LISTEN_NOT_VULN, appname, port);
else
  audit(AUDIT_NOT_LISTEN, appname, port);
