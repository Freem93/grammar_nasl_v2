#
# This script was written by Charles Thier <cthier@thethiers.net>
#
# GPLv2
#

# Changes by Tenable:
# - only attempt to login if the policy allows it (10/25/11)

include("compat.inc");

if(description)
{
   script_id(18415);
   script_version("$Revision: 1.15 $");
   script_cve_id("CVE-1999-0508");
   script_name(english:"Bay Networks Accelar 1200 Switch Default Password (password) for 'usrname' Account");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote network device can be accessed with default credentials." );
 script_set_attribute(attribute:"description", value:
"The remote device appears to be a Bay Networks Accelar 1200 Switch 
that can be accessed using default credentials.  An attacker could
leverage this issue to gain administrative access to the affected
device.  This password could also be potentially used to gain other
sensitive information about the network from the device." );
 # http://web.archive.org/web/20050209060646/http://www.cirt.net/cgi-bin/passwd.pl?method=showven&ven=Nortel
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35874295" );
 script_set_attribute(attribute:"solution", value:
"Telnet to the device and change the default password." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SNMP Community Scanner');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/03");
 script_cvs_date("$Date: 2015/09/24 20:59:26 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

 
   summary["english"] = "Logs into Bay Networks switches with default password";
   script_summary(english:summary["english"]);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright(english:"This script is Copyright (C) 2005-2015 Charles Thier");
   script_family(english:"Misc.");
   script_require_ports(23);
   exit(0);
}


#
# The script code starts here
#

include("telnet_func.inc");
usrname = "rwa";
password = "rwa";

port = 23;
if (! get_port_state(port)) exit(0, "TCP port "+port+" is closed.");
if ( get_kb_item("global_settings/supplied_logins_only") ) exit(0, "Policy is configured to prevent trying default user accounts");


tnb = get_telnet_banner(port:port);
if ( ! tnb ) exit(1, "No telnet banner on port "+port+".");

if ("Accelar 1200" >!< tnb) exit(0, "The remote Telnet server is not Accelar 1200.");

soc = open_sock_tcp(port);
if (! soc) exit(1, "TCP connection failed to port "+port+".");

                        answer = recv(socket:soc, length:4096);
                        if("ogin:" >< answer)
                        {
                                send(socket:soc, data:string(usrname, "\r\n"));
                                answer = recv(socket:soc, length:4096);
                                send(socket:soc, data:string(password, "\r\n"));
                                answer = recv(socket:soc, length:4096);
                                if("Accelar-1200" >< answer)
                                {
                                  report = string(
                                    "\n",
                                    "Nessus was able to gain access using the following credentials :\n",
                                    "\n",
                                    "  User     : ", usrname, "\n",
                                    "  Password : ", password, "\n"
                                  );
                                  security_hole(port:port, extra:report);
                                }
                        }
                close(soc);



