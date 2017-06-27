#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76409);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id("CVE-2014-1767");
  script_bugtraq_id(68394);
  script_osvdb_id(108829);
  script_xref(name:"MSFT", value:"MS14-040");

  script_name(english:"MS14-040: Vulnerability in Ancillary Function Driver (AFD) Could Allow Elevation of Privilege (2975684)");
  script_summary(english:"Checks version of Afd.sys");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a driver that allows elevation of
privilege.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of the Ancillary Function
Driver (afd.sys) that is affected by a privilege escalation
vulnerability. The flaw is due to the Ancillary Function Driver not
properly processing user-supplied input, leading to a double free
scenario, allowing a local attacker to elevate privileges by running a
specially crafted application.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-040");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-220/");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2003 SP2, Vista
SP2, 2008 SP2, 7 SP1, 2008 R2 SP1, 8, 2012, 8.1, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS14-040';

pp81kb = '2973408';
kb = '2961072';

subkbs = make_list(kb, pp81kb);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:subkbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 / Server 2012 R2 Pre-Patch
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"Afd.sys", version:"6.3.9600.16668", min_version:"6.3.9600.16000", dir:"\system32\drivers", bulletin:bulletin, kb:pp81kb) ||

  # Windows 8.1 / Server 2012 R2 Post-Patch
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"Afd.sys", version:"6.3.9600.17194", min_version:"6.3.9600.17000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows 8 / 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Afd.sys", version:"6.2.9200.21133", min_version:"6.2.9200.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Afd.sys", version:"6.2.9200.17014", min_version:"6.2.9200.16000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Afd.sys", version:"6.1.7601.22705", min_version:"6.1.7601.22000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Afd.sys", version:"6.1.7601.18489", min_version:"6.1.7600.17000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Afd.sys", version:"6.0.6002.23414", min_version:"6.0.6002.23000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Afd.sys", version:"6.0.6002.19115", min_version:"6.0.6002.18000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Afd.sys", version:"5.2.3790.5358", dir:"\system32\drivers", bulletin:bulletin, kb:kb)
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
