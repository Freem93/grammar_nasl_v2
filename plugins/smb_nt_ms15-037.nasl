#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82793);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/07/28 20:47:51 $");

  script_cve_id("CVE-2015-0098");
  script_bugtraq_id(73989);
  script_osvdb_id(120633);
  script_xref(name:"MSFT", value:"MS15-037");
  script_xref(name:"IAVA", value:"2015-A-0088");

  script_name(english:"MS15-037: Vulnerability in Windows Task Scheduler Could Allow Elevation of Privilege (3046269)");
  script_summary(english:"Checks for KB3046269 in the registry.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a privilege escalation
vulnerability due to improper handling of invalid tasks in the Task
Scheduler. If a known invalid task is present on the system, a local
attacker can exploit the task to cause Task Scheduler to execute a
crafted application with System privileges, possibly gaining further
rights.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-037");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 7 and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/15");

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
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS15-037';
kb = '3046269';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win7:'1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

systemroot = hotfix_get_systemroot();
if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

kb_listings = get_registry_subkeys(handle:hklm, key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages");

RegCloseKey(handle:hklm);
NetUseDel();

if (empty_or_null(kb_listings) || max_index(keys(kb_listings)) < 1) audit(AUDIT_REG_FAIL);

foreach entry (kb_listings)
{
  if ("KB3046269" >< entry || "KB3125574" >< entry)
  {
    audit(AUDIT_HOST_NOT, 'affected');
  }
}
# Vulnerable
report = '\n' + 'KB3046269 is not installed on this Windows 7 / Windows 2008 R2 system.' + '\n';
if (report_verbosity > 0) security_warning(port:0, extra:report);
else security_warning(0);
exit(0);

