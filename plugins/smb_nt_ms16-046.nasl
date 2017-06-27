#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(90439);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/07/18 20:50:59 $");

  script_cve_id("CVE-2016-0135");
  script_bugtraq_id(85911);
  script_osvdb_id(136976);
  script_xref(name:"MSFT", value:"MS16-046");
  script_xref(name:"IAVB", value:"2016-B-0067");

  script_name(english:"MS16-046: Security Update for Secondary Logon (3148538)");
  script_summary(english:"Checks the version of clipsvc.dll or audiodg.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an elevation of privilege
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by an elevation of privilege vulnerability in the
Windows Secondary Logon Service due to improper management of requests
in memory. An authenticated, remote attacker can exploit this, via a
specially crafted application, to gain elevated privileges, allowing
the execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-046");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

bulletin    = "MS16-046";
kb_win10    = "3147461";
kb_win10_t2 = "3147458";

kbs = make_list(kb_win10, kb_win10_t2);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

# Windows 10 and 10 T2
if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 10 T2 (aka 1511 or Threshold 2)
  hotfix_is_vulnerable(os:"10", sp:0, file:"audiodg.exe", version:"10.0.10586.218", min_version:"10.0.10586.0", dir:"\system32", bulletin:bulletin, kb:kb_win10_t2) ||

  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"ClipSVC.dll", version:"10.0.10240.16766", min_version:"10.0.10240.16000", dir:"\system32", bulletin:bulletin, kb:kb_win10)
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
