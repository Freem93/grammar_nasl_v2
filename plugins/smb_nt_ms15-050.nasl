#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83355);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/06 17:11:39 $");

  script_cve_id("CVE-2015-1702");
  script_bugtraq_id(74492);
  script_osvdb_id(122011);
  script_xref(name:"MSFT", value:"MS15-050");
  script_xref(name:"IAVA", value:"2015-A-0107");

  script_name(english:"MS15-050: Vulnerability in Service Control Manager Could Allow Elevation of Privilege (3055642)");
  script_summary(english:"Checks the version of services.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a privilege escalation
vulnerability in Windows Service Control Manager (SCM) due to improper
verification of impersonation levels. A local attacker can exploit
this, via a specially crafted application, to escalate their
privileges and make calls to SCM for which they lack sufficient
privilege.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-050");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, 2012, 8.1, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");

  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS15-050';

kbs = make_list("3055642");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# The 2k3 checks could flag XP 64, which is unsupported
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows XP" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

vuln = FALSE;
if ("2003" >< productname)
{
  info = '
The remote host is running Windows 2003, which is vulnerable to
MS15-050. Microsoft has no plans to release a fix for MS15-050 on
Windows 2003. No workarounds are available.\n';
  hotfix_add_report(info, bulletin:bulletin);
  vuln = TRUE;
}
else if (
  # Windows 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", file:"services.exe", version:"6.3.9600.17793", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3055642") ||

  # Windows 8 / 2012
  hotfix_is_vulnerable(os:"6.2", arch:"x64", file:"services.exe", version:"6.2.9200.21442", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3055642") ||
  hotfix_is_vulnerable(os:"6.2", arch:"x86", file:"services.exe", version:"6.2.9200.21456", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3055642") ||
  hotfix_is_vulnerable(os:"6.2", file:"services.exe", version:"6.2.9200.17343", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3055642") ||

  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"services.exe", version:"6.1.7601.23033", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3055642") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"services.exe", version:"6.1.7601.18829", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"3055642") ||

  # Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"services.exe", version:"6.0.6002.23677", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3055642") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"services.exe", version:"6.0.6002.19369", min_version:"6.0.6002.16000", dir:"\system32", bulletin:bulletin, kb:"3055642")
)
{
  vuln = TRUE;
}

if (vuln)
{
  if ('2003' >!< productname)
  {
    set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  }

  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
