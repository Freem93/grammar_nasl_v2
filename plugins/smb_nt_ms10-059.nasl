#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(48296);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/04/23 21:35:39 $");

  script_cve_id("CVE-2010-2554", "CVE-2010-2555");
  script_bugtraq_id(42259, 42269);
  script_osvdb_id(66977, 66978);
  script_xref(name:"IAVB", value:"2010-B-0064");
  script_xref(name:"MSFT", value:"MS10-059");

  script_name(english:"MS10-059: Vulnerabilities in the Tracing Feature for Services Could Allow Elevation of Privilege (982799)");
  script_summary(english:"Checks version of Rtutils.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has multiple privilege escalation
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Tracing Feature for Services on the remote host has the
following vulnerabilities :

  - Windows places incorrect ACLs on registry keys, which
    could allow an attacker to execute code with elevated
    privileges. (CVE-2010-2554)

  - Memory is allocated in an unspecified, unsafe manner
    when processing specially crafted long strings.  An
    attacker could exploit this to execute code with elevated
    privileges. (CVE-2010-2555)"
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-059");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS10-059';
kbs = make_list("982799");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = '982799';
if (
  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", file:"Rtutils.dll", version:"6.1.7600.20738", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", file:"Rtutils.dll", version:"6.1.7600.16617", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Rtutils.dll", version:"6.0.6002.22427", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Rtutils.dll", version:"6.0.6002.18274", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Rtutils.dll", version:"6.0.6001.22715", min_version:"6.0.6001.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Rtutils.dll", version:"6.0.6001.18495", min_version:"6.0.6000.16000", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:'SMB/Missing/MS10-059', value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
