#
# (C) Tenable Network Security, Inc.
#

#Ref:
# From: "morning_wood" <se_cur_ity@hotmail.com>
# To: <bugtraq@securityfocus.com>
# Subject: IRCXpro 1.0 - Clear local and default remote admin passwords
# Date: Tue, 3 Jun 2003 00:57:45 -0700


include("compat.inc");

if (description)
{
 script_id(11696);
 script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2015/06/23 19:16:51 $");
 script_bugtraq_id(7792);
 script_osvdb_id(4660);

 script_name(english:"IRCXPro Plaintext Passwords Local Disclosure");
 script_summary(english:"Checks settings.init");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote web server is running IRCXPro.

This software stores the list of user names and passwords in plaintext 
in \Program Files\IRCXPro\Settings.ini.

An attacker with a full access to this host may use this flaw to gain
the list of passwords of your users.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2003/Jun/45");
 script_set_attribute(attribute:"solution", value:"Upgrade to IRCXPro 1.1 or newer");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/06/03");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/03");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_require_ports(139, 445);
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");


rootfile = hotfix_get_programfilesdir();
if(!rootfile) exit(1);
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
db =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\IRCXPro\settings.ini", string:rootfile);


name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) exit(1);


handle = CreateFile (file:db, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 CloseFile(handle:handle);
 security_note(port);
}

NetUseDel();
