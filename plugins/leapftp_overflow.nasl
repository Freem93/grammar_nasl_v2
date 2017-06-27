#
# (C) Tenable Network Security, Inc.
#

# Ref:
# Date: Mon, 09 Jun 2003 12:19:40 +0900
# From: ":: Operash ::" <nesumin@softhome.net>
# To: bugtraq@securityfocus.com
# Subject: [LeapFTP] "PASV" Reply Buffer Overflow Vulnerability
#


include("compat.inc");

if (description)
{
 script_id(11705);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2015/01/12 17:12:45 $");
 script_bugtraq_id(7860);
 script_osvdb_id(4587);

 script_name(english:"LeapFTP < 2.7.4.x PASV Reply Remote Overflow");
 script_summary(english:"Determines the presence of LeapFTP");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running an FTP client that is affected by a buffer
overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host is running LeapFTP - an FTP client.

There is a flaw in the remote version of this software that could
allow an attacker to execute arbitrary code on this host.

To exploit it, an attacker would need to set up a rogue FTP server and
have a user on this host connect to it.");
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=105795219412333&w=2");
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.7.4.x or newer as this reportedly fixes the
issue.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'LeapWare LeapFTP v2.7.3.600 PASV Reply Client Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/06/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/09");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");



rootfile = hotfix_get_programfilesdir();
if(!rootfile) exit(1);
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\LeapFTP\LeapFTP.exe", string:rootfile);



name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();




if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) exit(1);


handle = CreateFile (file:exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 version = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( version[0] < 2 ||
      (version[0] == 2 && version[1] < 6 ) ||
      (version[0] == 2 && version[1] == 7 && version[2] <= 3 ) )
	security_hole(port);
}

NetUseDel();
