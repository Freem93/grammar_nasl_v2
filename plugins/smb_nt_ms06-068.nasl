#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(23645);
 script_version("$Revision: 1.27 $");
 script_cvs_date("$Date: 2015/04/23 21:04:51 $");

 script_cve_id("CVE-2006-3445");
 script_bugtraq_id(21034);
 script_osvdb_id(30262);
 script_xref(name:"MSFT", value:"MS06-068");

 script_name(english:"MS06-068: Vulnerability in Microsoft Agent Could Remote Code Execution (920213)");
 script_summary(english:"Determines the presence of update 920213");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute arbitrary code on the remote host through the
agent service.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in the Microsoft Agent service
that could allow an attacker to execute arbitrary code on the remote host.

To exploit this flaw, an attacker would need to set up a rogue website and
lure a victim on the remote host into visiting it or have him load a malformed
.ACF file.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-068");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/11/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/14");

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

bulletin = 'MS06-068';
kb = '920213';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2', win2003:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if ( ( hotfix_check_fversion(file:"msagent\Agentsvr.exe", version:"2.0.0.3424", bulletin:bulletin, kb:kb) == HCF_OLDER ) ||
     ( hotfix_check_fversion(file:"msagent\Agentsvr.exe", version:"5.2.3790.1242", min_version:"5.2.3790.0", bulletin:bulletin, kb:kb) == HCF_OLDER ) )
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
