#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(11616);
 script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2016/10/10 15:57:04 $");
 script_bugtraq_id(7040);
 script_osvdb_id(58839);

 script_name(english:"DBTools DBManager catalog.mdb Plaintext Local Credential Disclosure");
 script_summary(english:"Determines the presence of DBManager.exe");

 script_set_attribute(attribute:"synopsis", value:
"The database manager on the remote host has an information disclosure
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host is running DBManager from DBTool - a GUI to manage
MySQL and PostgreSQL databases.

This program stores the passwords and IP addresses of the managed
databases in an unencrypted file. A local attacker could use the data
in this file to log into the managed databases and execute arbitrary
SQL queries.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Mar/118");
 script_set_attribute(attribute:"solution", value:"There is no solution at this time.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Databases");
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
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
if ( ! rootfile ) exit(0);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\DBTools Software\DBManager Professional\DBManager.exe", string:rootfile);



login	= kb_smb_login();
pass  	= kb_smb_password();
domain 	= kb_smb_domain();
port    = kb_smb_transport();

if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) exit(1);


handle = CreateFile (file:exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 security_note(port);
 CloseFile(handle:handle);
}

NetUseDel();
