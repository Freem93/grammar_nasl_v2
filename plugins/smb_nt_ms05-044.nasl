#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(19997);
 script_version("$Revision: 1.30 $");
 script_cvs_date("$Date: 2015/05/07 12:06:03 $");

 script_cve_id("CVE-2005-2126");
 script_bugtraq_id(12160);
 script_osvdb_id(19901);
 script_xref(name:"MSFT", value:"MS05-044");
 script_xref(name:"CERT", value:"415828");

 script_name(english:"MS05-044: Vulnerability in the Windows FTP Client Could Allow File Transfer Location Tampering (905495)");
 script_summary(english:"Determines the presence of update 905495");

 script_set_attribute(attribute:"synopsis", value:
"A flaw in the FTP client installed on the remote host could allow a
rogue FTP server to write to arbitrary locations on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Microsoft FTP client that
contains a flaw in the way it handles FTP download.  An attacker could
exploit this flaw to modify the destination location for files
downloaded via FTP.

To exploit this flaw an attacker would need to set up a rogue FTP server
and have a victim on the remote host connect to it and download a file
manually using the affected client.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms05-044");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/11");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/10/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS05-044';
kb = '905495';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_NOTE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'1', win2003:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

version = hotfix_check_ie_version();
if (!version) exit(1, "Failed to get the version of Internet Explorer.");
if (!egrep(pattern:"^6\.", string:version)) exit(0, "The installed version of Internet Explorer is not 6.x.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.2", sp:0, file:"msieftp.dll", version:"6.0.3790.383", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:1, file:"msieftp.dll", version:"6.0.2800.1724", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0",       file:"msieftp.dll", version:"5.50.4956.500", min_version:"5.50.0.0", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_note();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
