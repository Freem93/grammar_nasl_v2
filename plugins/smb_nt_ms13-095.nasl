#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70853);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/04/23 21:44:06 $");

  script_cve_id("CVE-2013-3869");
  script_bugtraq_id(63561);
  script_osvdb_id(99649);
  script_xref(name:"MSFT", value:"MS13-095");
  script_xref(name:"IAVB", value:"2013-B-0128");

  script_name(english:"MS13-095: Vulnerability in Digital Signatures Could Allow Denial of Service (2868626)");
  script_summary(english:"Checks version of Crypt32.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host is affected by a denial of service
vulnerability.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is affected by a denial of service
vulnerability due to the way affected web services process specially
crafted X.509 certificates.  By exploiting this flaw, a remote,
unauthenticated attacker could crash the affected service."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-095");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008 SP2, 7, 2008 R2, 8, 2012, 8.1 and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS13-095';
kb = '2868626';

kbs = make_list(kb);
if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/WindowsVersion');
if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 and Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"crypt32.dll", version:"6.3.9600.16431", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 8 and Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"crypt32.dll", version:"6.2.9200.20838", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"crypt32.dll", version:"6.2.9200.16727", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"crypt32.dll", version:"6.1.7601.22473", min_version:"6.1.7601.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"crypt32.dll", version:"6.1.7601.18277", min_version:"6.1.7600.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"crypt32.dll", version:"6.0.6002.23235", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"crypt32.dll", version:"6.0.6002.18953", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"crypt32.dll", version:"5.131.3790.5235", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"crypt32.dll", version:"5.131.2600.6459", dir:"\system32", bulletin:bulletin, kb:kb)
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
