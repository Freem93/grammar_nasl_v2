#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(20906);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2015/04/23 21:04:50 $");

 script_cve_id("CVE-2006-0005");
 script_bugtraq_id(16644);
 script_osvdb_id(23132);
 script_xref(name:"CERT", value:"692060");
 script_xref(name:"MSFT", value:"MS06-006");

 script_name(english:"MS06-006: Vulnerability in Windows Media Player Plug-in Could Allow Remote Code Execution (911564)");
 script_summary(english:"Checks the version of Media Player");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Media
Player.");
 script_set_attribute(attribute:"description", value:
"The remote host is running the Windows Media Player plug-in.

There is a vulnerability in the remote version of this software that
could allow an attacker to execute arbitrary code on the remote host.

To exploit this flaw, an attacker would need to send a specially
crafted media file with a rogue EMBED element and have a user on the
affected host open it with the plug-in.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-006");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/02/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/14");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS06-006';
kbs = make_list("911564");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'1,2', win2003:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

path = get_kb_item_or_exit("SMB/WindowsMediaPlayer_path");

share = hotfix_path2share(path:path);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = '911564';

if ( hotfix_check_fversion(path:path, file:"Npdsplay.dll", version:"3.0.2.629", bulletin:bulletin, kb:kb) == HCF_OLDER )
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
