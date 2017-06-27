#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17212);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2015/01/12 17:12:47 $");

  script_cve_id("CVE-2005-0545");
  script_bugtraq_id(12641);
  script_osvdb_id(14182);

  script_name(english:"OFF2000: Office Programs Can Browse Restricted Drives (302753)");
  script_summary(english:"Determines the version of MSO9.dll");

  script_set_attribute(attribute:'synopsis', value:"The remote host is vulnerable to an inforamtion disclosure attack.");
  script_set_attribute(attribute:'description', value:
"The remote host is running a version of Microsoft Office that contains
a security flaw that could allow a user to browse restricted drives.

An attacker could exploit this flaw to gain access to files he would
otherwise not have access to.");
  script_set_attribute(attribute:'see_also', value:"http://marc.info/?l=bugtraq&m=110935549821930&w=2");
  script_set_attribute(attribute:'see_also', value:"http://support.microsoft.com/?id=302753");
  script_set_attribute(attribute:'solution', value:"Contact Microsoft for the relevant hotfix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
  script_family(english:"Windows");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");

# nb: Microsoft's KB says only Windows 2000 and Windows Server 2003 Standard Edition are affected.
if (hotfix_check_sp(win2k:6, win2003:2) <= 0) exit(0, "Host is not affected based on its version / service pack.");

rootfile = hotfix_get_programfilesdir();
if(!rootfile) exit(1);

version = hotfix_check_office_version();
if ( !version || (version["9.0"]) )
  if ( ! hotfix_check_works_installed() ) exit(1);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Office\Office\mso9.dll", string:rootfile);


login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 )
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

handle = CreateFile (file:dll,  desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);


if( ! isnull(handle)  )
{
 v = GetFileVersion( handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) )
 {
  if ( v[0] == 9 && v[1] == 0 && v[2] == 0 && v[3] < 4625 )
	 security_hole(port);
 }
 else
 {
  NetUseDel();
  exit(1);
 }
}

NetUseDel();
