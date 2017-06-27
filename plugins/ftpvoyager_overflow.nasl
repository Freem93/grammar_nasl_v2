#
# (C) Tenable Network Security, Inc.
#

# Ref:
#
# Date: Mon, 09 Jun 2003 12:19:41 +0900
# From: ":: Operash ::" <nesumin@softhome.net>
# To: bugtraq@securityfocus.com
# Subject: [FTP Voyager] File List Buffer Overflow Vulnerability
#


include("compat.inc");

if (description)
{
 script_id(11711);
 script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2015/01/12 17:12:44 $");
 script_bugtraq_id(7862);
 script_osvdb_id(4584);

 script_name(english:"FTP Voyager LIST Command File List Handling Remote Overflow");
 script_summary(english:"Determines the presence of FTP Voyager");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running an FTP client that is affected by a remote
buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host is running FTP Voyager - an FTP client.

The version installed is earlier than 10.0.0.1. Such versions are
reportedly affected by a buffer overflow vulnerability. An attacker
could exploit this flaw in order to execute arbitrary code on this
host.

To exploit it, an attacker would need to set up a rogue FTP server and
have a user on this host connect to it.");
 script_set_attribute(attribute:"solution", value:"Upgrade to version FTP Voyager 10.0.0.1 or newer.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/06/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/05/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/10");

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


include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");

rootfile = hotfix_get_programfilesdir();
if ( ! rootfile ) exit(1);


share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\RhinoSoft.com\FTP Voyager\FTPVoyager.exe", string:rootfile);


name 	= kb_smb_name();
login	= kb_smb_login();
pass  	= kb_smb_password();
domain 	= kb_smb_domain();
port    = kb_smb_transport();
#if(!get_port_state(port))exit(1);
#soc = open_sock_tcp(port);
#if(!soc)exit(1);

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) exit(1);

handle = CreateFile (file:exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 version = GetFileVersion(handle:handle);
 CloseFile(handle:handle);

 if ( !isnull(version) )
 {
  if ( version[0] < 10 ||
     (version[0] == 10 && version[1] == 0 && version[2] == 0 && version[3] == 0 ) ) security_hole(port);
 }
}


NetUseDel();
