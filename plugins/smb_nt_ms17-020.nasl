#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97734);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/26 23:57:36 $");

  script_cve_id("CVE-2017-0045");
  script_bugtraq_id(96103);
  script_osvdb_id(153679);
  script_xref(name:"MSFT", value:"MS17-020");
  script_xref(name:"MSKB", value:"3205715");
  script_xref(name:"MSKB", value:"4012212");
  script_xref(name:"MSKB", value:"4012215");
  script_xref(name:"IAVB", value:"2017-B-0030");

  script_name(english:"MS17-020: Security Update for Windows DVD Maker (3208223)");
  script_summary(english:"Checks the version of dvdmaker.exe or the installed rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by an information disclosure vulnerability in
Windows DVD Maker due to improper parsing of .msdvd files. An
unauthenticated, remote attacker can exploit this issue, by convincing
a user to execute a specially crafted application, to disclose
sensitive information.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS17-020");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista and 7.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "smb_check_rollup.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS17-020';
kbs = make_list(
  '3205715',
  '4012212',
  '4012215'
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
version = get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
# Windows Server 2008 and 2008 R2 are not affected.
if ("Server 2008" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;

# Windows Vista
if ("6.0" >< version) {
  path = hotfix_get_programfilesdir();
  path = hotfix_append_path(path:path, value:"\Movie Maker\");
  if (
      (hotfix_check_fversion(file:"dvdmaker.exe", version:"6.0.6002.19725", min_version:"6.0.6002.18000", path:path, bulletin:bulletin, kb:'3205715', product:'Windows DVD Maker') == HCF_OLDER) ||
      (hotfix_check_fversion(file:"dvdmaker.exe", version:"6.0.6002.24048", min_version:"6.0.6002.23000", path:path, bulletin:bulletin, kb:'3205715', product:'Windows DVD Maker') == HCF_OLDER)
  ) vuln++;
}

# Windows 7
if (smb_check_rollup(os:"6.1",
                     sp:1,
                     rollup_date: "03_2017",
                     bulletin:bulletin,
                     rollup_kb_list:make_list(4012212, 4012215))
) vuln++;

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
