#
# (C) Tenable Network Security, Inc.
#
# Ref:
#  From: "Andreas Constantinides" <megahz@megahz.org>
#  To: <bugtraq@securityfocus.com>
#  Subject: Plaintext Password in Settings.ini of CesarFTP
#  Date: Tue, 20 May 2003 10:25:56 +0300


include("compat.inc");


if (description)
{
 script_id(11640);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2016/11/15 13:39:08 $");
 script_cve_id("CVE-2001-1336", "CVE-2003-0329");
 script_osvdb_id(12056);


 script_name(english:"CesarFTP settings.ini Authentication Credential Plaintext Disclosure");
 script_summary(english:"Determines the presence of CesarFTP's settings.ini");

 script_set_attribute(attribute:"synopsis", value:"The remote FTP server is storing unencrypted passwords on disk.");
 script_set_attribute(attribute:"description", value:
"The remote host is running CesarFTP.

Due to a design flaw in the program, the plaintext usernames and
passwords of FTP users are stored in the file 'settings.ini'. Any user
with an account on this host may read this file and use the password
to connect to this FTP server.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/May/248");
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2003/May/211"
 );
 script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/05/28");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/20");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:aclogic:cesarftp");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");

rootfile = hotfix_get_programfilesdir();
if ( ! rootfile ) exit(0);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\CesarFTP\Settings.ini", string:rootfile);


name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();




if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) exit(0);

handle = CreateFile (file:exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 data = ReadFile(handle:handle, length:16384, offset:0);
 if('Password= "' >< data && 'Login= "' >< data) security_note(port);
 CloseFile(handle:handle);
}

NetUseDel();

