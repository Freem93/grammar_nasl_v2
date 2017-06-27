#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(11583);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2015/01/12 17:12:47 $");
 script_bugtraq_id(7402);
 script_osvdb_id(11936);

 script_name(english:"Microsoft Windows shlwapi.dll Malformed HTML Tag Handling Null Pointer DoS");
 script_summary(english:"Checks for the version of shlwapi.dll");

 script_set_attribute(attribute:"synopsis", value:"It is possible to crash the remote web client.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the shlwapi.dll which crashes
when processing a malformed HTML form.

An attacker may use this flaw to prevent the users of this host from
working properly.

To exploit this flaw, an attacker would need to send a malformed HTML
file to the remote user, either by email or by making the user visit a
rogue website.");
 script_set_attribute(attribute:"solution", value:"None");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/04/21");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/06");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_exclude_keys("SMB/samba");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");


rootfile = hotfix_get_systemroot();
if ( ! rootfile ) exit(1);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\shlwapi.dll", string:rootfile);



name 	= kb_smb_name();
login	= kb_smb_login();
pass  	= kb_smb_password();
domain 	= kb_smb_domain();
port    = kb_smb_transport();




if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) exit(1);


handle = CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if ( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) )
 {
  if ( v[0] < 6 || (v[0] == 6 && v[1] == 0 && (v[2] < 2800 || ( v[2] == 2800 && v[3] < 1106 ) ) ) )
	security_warning( port );
 }
 else {
	NetUseDel();
	exit(1);
      }
}

NetUseDel();
