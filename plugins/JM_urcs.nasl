#
# This script was written by Joseph Mlodzianowski <joseph@rapter.net>
# 

# Changes by Tenable:
# - Revised plugin title (12/28/10)

include("compat.inc");

if(description)
{
 script_id(15405);
 script_version("$Revision: 1.19 $");
 script_name(english:"Unmanarc Remote Control Server (URCS) Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host may have been compromised." );
 script_set_attribute(attribute:"description", value:
"This host appears to be running Unmanarc Remote Control Server (URCS). 
While it does have some legitimate uses, URCS may also have been
installed silently as a backdoor, which may allow an intruder to gain
remote access to files on the remote system.  If this program was not
installed for remote management, then it means the remote host has
been compromised. 

An attacker may use it to steal files, passwords, or redirect ports on
the remote system to launch other attacks." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/projects/urcs" );
  # http://web.archive.org/web/20040924221505/http://urcs.unmanarc.com/
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ddf2497d" );
  # http://www.symantec.com/security_response/writeup.jsp?docid=2003-050220-4646-99
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43608c3f" );
 script_set_attribute(attribute:"solution", value:
"Reinstall the operating system and files from backup unless URCS is
intended to be installed." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/01");
 script_cvs_date("$Date: 2013/01/30 17:04:32 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Determines the presence of the URCS Server");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright(C) 2004-2013 J.Mlodzianowski");
 script_family(english:"Backdoors");
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/unknown", 3360);
 exit(0);
}

#
# The code starts here:
#

include("misc_func.inc");
include('global_settings.inc');

if ( ! thorough_tests || get_kb_item("global_settings/disable_service_discovery")  )
{
 port = 3360;
}
else
{
 port = get_unknown_svc(3360);
 if ( ! port ) exit(0);
}
# Default port for URCS Server is 3360
# Default port for URCS Client is 1980
 if (get_port_state(port))
{
 soc= open_sock_tcp(port);
 if(soc)
{
 send(socket:soc, data:'iux');
 r = recv(socket:soc, length:817);
 if ( "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" >< r ) 
	security_hole(port);
 close(soc);
 }
} 
