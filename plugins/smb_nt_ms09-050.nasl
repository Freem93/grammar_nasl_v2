#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42106);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2017/04/19 13:27:09 $");

  script_cve_id("CVE-2009-2526", "CVE-2009-2532", "CVE-2009-3103");
  script_bugtraq_id(36299, 36594, 36595);
  script_osvdb_id(57799, 58875, 58876);
  script_xref(name:"MSFT", value:"MS09-050");
  script_xref(name:"CERT", value:"135940");
  script_xref(name:"EDB-ID", value:"9594");
  script_xref(name:"EDB-ID", value:"10005");
  script_xref(name:"EDB-ID", value:"12524");
  script_xref(name:"EDB-ID", value:"14674");
  script_xref(name:"EDB-ID", value:"16363");

  script_name(english:"MS09-050: Vulnerabilities in SMBv2 Could Allow Remote Code Execution (975517) (EDUCATEDSCHOLAR)");
  script_summary(english:"Checks version of srv2.sys");

  script_set_attribute(attribute:"synopsis", value:"The remote SMB server can be abused to execute code remotely.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a vulnerable SMBv2 implementation with
the following issues :

  - A specially crafted SMBv2 packet can cause an
    infinite loop in the Server service.  A remote,
    unauthenticated attacker can exploit this to cause
    a denial of service. (CVE-2009-2526)

  - Sending a specially crafted SMBv2 packet to the Server
    service can result in code execution.  A remote,
    unauthenticated attacker can exploit this to take
    complete control of the system. (CVE-2009-2532,
    CVE-2009-3103) (EDUCATEDSCHOLAR)

EDUCATEDSCHOLAR is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2017/04/14 by a group known as the Shadow
Brokers.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-050");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows Vista and 2008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS09-050 Microsoft SRV2.SYS SMB Negotiate ProcessID Function Table Dereference');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");
  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

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

bulletin = 'MS09-050';
kb = '975517';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'0,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Vista SP0 (x86 & x64)
  hotfix_is_vulnerable(os:"6.0",   file:"srv2.sys", version:"6.0.6000.16927",   min_version:"6.0.6000.0", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",   file:"srv2.sys", version:"6.0.6000.21127",   min_version:"6.0.6000.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Vista / 2k8 SP1 (x86 & x64)
  hotfix_is_vulnerable(os:"6.0",   file:"srv2.sys", version:"6.0.6001.18331",   min_version:"6.0.6001.0", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",   file:"srv2.sys", version:"6.0.6001.22522",   min_version:"6.0.6001.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Vista / 2k8 SP2 (x86 & x64)
  hotfix_is_vulnerable(os:"6.0",   file:"srv2.sys", version:"6.0.6002.18112",   min_version:"6.0.6002.0", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",   file:"srv2.sys", version:"6.0.6002.22225",   min_version:"6.0.6002.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb)
)
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
