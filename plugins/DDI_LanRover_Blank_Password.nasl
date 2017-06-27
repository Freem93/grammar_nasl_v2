#
# This script was written by H D Moore <hdmoore@digitaldefense.net>
#
# See the Nessus Scripts License for details
#

include("compat.inc");

if(description)
{
 script_id(10998);
 script_version ("$Revision: 1.10 $");
 script_cvs_date("$Date: 2016/02/04 22:38:29 $");

 script_cve_id("CVE-1999-0508");
 script_osvdb_id(820);
 
 script_name(english:"Shiva LanRover Blank Password");
 script_summary(english:"Checks for a blank password for the root account");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote network device does not use an administrative password.");
 script_set_attribute(attribute:"description", value:
"The Shiva LanRover has no password set for the root user account.  An
attacker is able to telnet to this system and gain access to any phone
lines attached to this device.  

Additionally, the LanRover can be used as a relay point for further
attacks via the telnet and rlogin functionality available from the
administration shell.");
 script_set_attribute(attribute:"solution", value:
"Telnet to this device and change the password for the root account via
the passwd command.  Please ensure any other accounts have strong
passwords set.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SNMP Community Scanner');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value:
"2002/06/05");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002-2016 Digital Defense Incorporated");

 script_family(english:"Misc.");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/telnet", 23);
 exit(0);
}

include('telnet_func.inc');
port = 23;
if(!get_port_state(port))exit(0);

banner = get_telnet_banner(port:port);
if ( ! banner || "@ Userid:" >!< r ) exit(0);

soc = open_sock_tcp(port);

if(soc)
{
    r = telnet_negotiate(socket:soc);

    if("@ Userid:" >< r)
    { 
        send(socket:soc, data:string("root\r\n"));
        r = recv(socket:soc, length:4096);
        
        if("Password?" >< r)
        {
            send(socket:soc, data:string("\r\n"));
            r = recv(socket:soc, length:4096);

            if ("Shiva LanRover" >< r)
            {
                security_hole(port:port);
            }
       }
    }
    close(soc);
}
