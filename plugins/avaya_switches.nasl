#
# This script was written by Charles Thier <cthier@thethiers.net>
#
# GPLv2
#


include("compat.inc");

if(description)
{
    script_id(17638);
    script_version("$Revision: 1.11 $");
    script_cvs_date("$Date: 2012/08/15 21:05:11 $");
    script_cve_id("CVE-1999-0508");
    script_name(english:"Avaya P330 Stackable Switch Default Password");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote switch can be accessed with default root credentials." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be an Avaya P330 Stackable Switch with its
default password set. 

An attacker could use this default password to gain remote access to
the affected switch.  This password could also be potentially used to
gain other sensitive information about the remote network from the
switch." );
 script_set_attribute(attribute:"see_also", value:"http://www.phenoelit-us.org/dpl/dpl.html" );
 script_set_attribute(attribute:"solution", value:
"Telnet to this switch and change the default password." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SNMP Community Scanner');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/28");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
   summary["english"] = "Logs into Avaya switches with default password";
   script_summary(english:summary["english"]);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright(english:"This script is Copyright (C) 2005-2012 Charles Thier");
   script_family(english:"Misc.");
   script_require_ports(23);
   exit(0);
}


#
# The script code starts here
#

include("telnet_func.inc");
usrname = string("root\r\n");
password = string("root\r\n");

port = 23;
if(get_port_state(port))
{
	tnb = get_telnet_banner(port:port);
	if ( ! tnb ) exit(0);
        if ("Welcome to P330" >< tnb)
        {
                soc = open_sock_tcp(port);
                if(soc)
                {
                        answer = recv(socket:soc, length:4096);
                        if("ogin:" >< answer)
                        {
                                send(socket:soc, data:usrname);
                                answer = recv(socket:soc, length:4096);
                                send(socket:soc, data:password);
                                answer = recv(socket:soc, length:4096);
                                if("Password accepted" >< answer)
                                {
                                        security_hole(port:23);
                                }
                        }
                close(soc);
                }

        }
}

