#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(93651);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id("CVE-2016-3375");
  script_bugtraq_id(92835);
  script_osvdb_id(144155);
  script_xref(name:"MSFT", value:"MS16-116");
  script_xref(name:"IAVA", value:"2016-A-0245");

  script_name(english:"MS16-116: Security Update in OLE Automation for VBScript Scripting Engine (3188724)");
  script_summary(english:"Checks the versions of Oleaut32.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by a remote code execution vulnerability in the
Microsoft OLE Automation mechanism and the VBScript Scripting
Engine due to improper handling of objects in memory. An
unauthenticated, remote attacker can exploit this, by convincing a
user to visit a specially crafted website, to execute arbitrary code
in context of the current user.

Note that MS16-104 must also be installed in order to fully resolve
the vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms16-116");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms16-104");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Vista, 2008, 7, 2008 R2,
2012, 8.1, RT 8.1, 2012 R2, and 10");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

bulletin = 'MS16-116';
kbs = make_list(
  "3184122",
  "3185611", # win10 RTM
  "3185614", # win10 1151
  "3189866"  # win10 1607
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "Windows 8.1" >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # 10 threshold 3 (aka 1607)
  hotfix_is_vulnerable(os:"10", sp:0, file:"win32kfull.sys", version:"10.0.14393.187", os_build:"14393", dir:"\system32", bulletin:bulletin, kb:"3189866") ||

  # 10 threshold 2 (aka 1511)
  hotfix_is_vulnerable(os:"10", sp:0, file:"win32kfull.sys", version:"10.0.10586.589", os_build:"10586", dir:"\system32", bulletin:bulletin, kb:"3185614") ||

  # 10 RTM
  hotfix_is_vulnerable(os:"10", sp:0, file:"win32kfull.sys", version:"10.0.10240.17113", os_build:"10240", dir:"\system32", bulletin:bulletin, kb:"3185611") ||

  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"Oleaut32.dll", version:"6.3.9600.18434", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3184122") ||

  # Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Oleaut32.dll", version:"6.2.9200.21950", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3184122") ||

  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Oleaut32.dll", version:"6.1.7601.23512", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"3184122") ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Oleaut32.dll", version:"6.0.6002.24007", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3184122") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Oleaut32.dll", version:"6.0.6002.19680", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3184122")
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
