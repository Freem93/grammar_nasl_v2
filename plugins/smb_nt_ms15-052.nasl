#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(83361);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/07/19 04:39:47 $");

  script_cve_id("CVE-2015-1674");
  script_bugtraq_id(74488);
  script_osvdb_id(122017);
  script_xref(name:"MSFT", value:"MS15-052");

  script_name(english:"MS15-052: Vulnerability in Windows Kernel Could Allow Security Feature Bypass (3050514)");
  script_summary(english:"Checks the version of cng.sys.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a security bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a security feature bypass
vulnerability due to a failure to properly validate memory addresses
by the Windows kernel. A remote attacker can exploit this flaw, via a
specially crafted application, to bypass the Kernel Address Space
Layout Randomization (KASLR), resulting in the disclosure of the base
address of the Cryptography Next Generation (CNG) kernel-mode driver
(cng.sys).");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-052");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 8, 2012, 8.1, and
2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS15-052';
kb  = "3050514";
kbs = make_list(kb);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"cng.sys", version:"6.3.9600.17785", min_version:"6.3.9600.16000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"cng.sys", version:"6.2.9200.21456", min_version:"6.2.9200.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"cng.sys", version:"6.2.9200.17343", min_version:"6.2.9200.16000", dir:"\system32\drivers", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
