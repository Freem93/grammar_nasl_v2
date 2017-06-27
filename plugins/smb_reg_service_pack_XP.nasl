#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
# Modified by David Maciejak <david dot maciejak at kyxar dot fr> to add check for Service Pack 2
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Updated to use compat.inc, updated security_note to use 'extra' arg (11/20/09)
# - Updated title (12/17/09)
# - Updated title (3/2/11)
# - Updated to account for POSReady 2009 (5/16/16)

include("compat.inc");

if (description)
{
 script_id(11119);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2016/05/16 21:15:51 $");

 script_bugtraq_id(10897);
 
 script_name(english:"Microsoft Windows SMB Registry : XP Service Pack Detection");
 script_summary(english:"Determines the remote SP.");
 
 script_set_attribute(attribute:"synopsis", value:
"It was possible to determine the service pack installed on the remote
system.");
 script_set_attribute(attribute:"description", value:
"Nessus was able to determine the Service Pack version of the Windows
XP system by reading the following registry key :

HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\CSDVersion");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");
 
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/09/12");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2002-2016 Alert4Web.com");

 script_dependencies("smb_reg_service_pack.nasl");
 script_require_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);

 exit(0);
}

#

if ( get_kb_item("SMB/RegOverSSH") ) exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 139;

win = get_kb_item("SMB/WindowsVersion"); 
if (!win) exit(0);

sp = get_kb_item("SMB/CSDVersion");

name = tolower(get_kb_item("SMB/ProductName"));

if(win == "5.1" && "embedded" >!< name)
{
 if (sp)
   set_kb_item(name:"SMB/WinXP/ServicePack", value:sp);

  report = string ("\n",
		"The remote Windows XP system has ", sp , " applied.\n");

  security_note(extra:report, port:port);
}
