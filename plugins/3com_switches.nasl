#
# This script was written by Patrik Karlsson <patrik.karlsson@ixsecurity.com>
# Enhancements by Tomi Hanninen
#
# Changes by Tenable:
# - Revised CVSS score and updated severity.

include("compat.inc");

if (description)
{
  script_id(10747);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2013/12/16 21:34:18 $");

  script_cve_id("CVE-1999-0508");
  script_osvdb_id(620);

  script_name(english:"3Com Superstack 3 Switch Multiple Default Accounts");
  script_summary(english:"Logs into 3Com Superstack 3 switches with default passwords.");

  script_set_attribute(attribute:"synopsis", value:"The remote switch has accounts with default passwords set.");
  script_set_attribute(attribute:"description", value:
"The 3Com Superstack 3 switch has the default passwords set. 

The attacker could use these default passwords to gain remote access to
your switch and then reconfigure the switch.  These passwords could also
be potentially used to gain sensitive information about your network
from the switch.");
  script_set_attribute(attribute:"solution", value:"Set a strong password for the accounts.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SNMP Community Scanner');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/08/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2001-2013 Patrik Karlsson");
  script_family(english:"Misc.");

  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports(23);

   exit(0);
}

include("audit.inc");
include("global_settings.inc");
include('telnet_func.inc');

port = 23; # the port can't be changed
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

banner = get_telnet_banner(port:port);
if ( "Login : " >!< banner ) audit(AUDIT_HOST_NOT, "a 3Com Superstack 3 switch");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

login[0] = string("monitor");
login[1] = string("manager");
login[2] = string("security");
login[3] = string("admin");

password[0] = string("monitor");
password[1] = string("manager");
password[2] = string("security");
password[3] = string("");

bfound = 0;

res = string("Standard passwords were found on this 3Com Superstack switch.\n");
res = res + string("The passwords found are:\n\n");

for ( i=0; i<4; i = i + 1 )
{
  soc = open_sock_tcp(port);
  if (soc)
  {
    r = recv(socket:soc, length:160);
    if("Login: " >< r)
    {
      tmp = string(login[i], "\r\n");
      send(socket:soc, data:tmp);
      r = recv_line(socket:soc, length:2048);
      tmp = string(password[i], "\r\n");
      send(socket:soc, data:tmp);
      r = recv(socket:soc, length:4096);

      if ( "logout" >< r )
      {
        bfound = 1;
        res = string(res, login[i], ":", login[i], "\n");
      }
    }
    close(soc);
  }
}

if (bfound == 1)
{
  if (report_verbosity > 0) security_hole(port:port, extra:res);
  else security_hole(port);
}
else audit(AUDIT_HOST_NOT, "affected");
