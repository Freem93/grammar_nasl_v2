#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10186);
 script_version ("$Revision: 1.29 $");
 script_cvs_date("$Date: 2013/01/25 01:19:09 $");

 script_name(english:"Portal of Doom Backdoor Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is infected by a Trojan horse." );
 script_set_attribute(attribute:"description", value:
"Portal of Doom is installed. 

This backdoor allows anyone to partially take the control of 
the remote system.

An attacker may use it to steal your password or prevent your from 
working properly." );
 script_set_attribute(attribute:"solution", value:
"open the registry to
HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices 
and look for the value named 'String' with the data 
'c:\windows\system\ljsgz.exe'. 
Boot into DOS mode and delete the c:\windows\system\ljsgz.exe file, 
then boot into Windows and delete the 'String' value from the registry.
If you are running Windows NT and are infected, you can kill the process
with Task Manager, and then remove the 'String' registry value." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/07/09");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english: "Checks for the presence of Portal of Doom");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2013 Tenable Network Security, Inc.");
 script_family(english: "Backdoors");
 script_dependencie("find_service1.nasl");
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

#
# The script code starts here
#

include('global_settings.inc');
if ( ! thorough_tests ) exit(0);

port = 10167;
if(get_udp_port_state(port))
{
 soc = open_sock_udp(port);
 if(soc)
 {
 data = "pod";
 send(socket:soc, data:data, length:3);
 r = recv(socket:soc, length:3);
 if("@" >< r)security_hole(port:port, protocol:"udp");
 close(soc);
 }
}
