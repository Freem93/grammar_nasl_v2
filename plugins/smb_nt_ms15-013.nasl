#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81266);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/01/28 22:37:18 $");

  script_cve_id("CVE-2014-6362");
  script_bugtraq_id(72467);
  script_osvdb_id(118185);
  script_xref(name:"MSFT", value:"MS15-013");
  script_xref(name:"IAVB", value:"2015-B-0018");

  script_name(english:"MS15-013: Vulnerability in Microsoft Office Could Allow Security Feature Bypass (3033857)");
  script_summary(english:"Checks the version of msosec.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a security bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office installed on the remote host is affected by a
security bypass vulnerability due to a failure to use the Address
Space Layout Randomization (ASLR) security feature. By convincing a
user to open a specially crafted Office file, a remote attacker can
use this flaw to predict the memory offsets of specific instructions
in a given call stack. The attacker can then utilize this information
to more easily exploit additional vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-013");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2007, 2010, and
2013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS15-013';

kbs = make_list(
  "2910941",
  "2920748",
  "2920795",
  "3033857"
);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated');

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

office_ver = hotfix_check_office_version();

vuln = 0;
# Assemble base office paths
installs = get_kb_list("SMB/Office/*/Path");
if (isnull(installs))  audit(AUDIT_HOST_NOT, 'affected');
foreach install (keys(installs))
{
  keyvalue = installs[install];
  if (empty_or_null(paths))
  {
    paths = make_list(keyvalue);
  }
  else
  {
    paths = make_list(paths, keyvalue);
  }
}
paths = list_uniq(paths);

foreach path (paths)
{
  # Office 2013 SP0 or SP1
  if (office_ver['15.0'])
  {
    office_sp = get_kb_item("SMB/Office/2013/SP");
    if (!isnull(office_sp) && (office_sp == 0 || office_sp == 1))
    {
      if (hotfix_is_vulnerable(file:"msosec.dll", version:"7.10.5078.0", min_version:'7.0.0.0', path:path + "ADDINS", bulletin:bulletin, kb:"2910941")) vuln++;
    }
  }

  # Office 2010 SP2
  if (office_ver['14.0'])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && (office_sp == 2))
    {
      if (hotfix_is_vulnerable(file:"msosec.dll", version:"7.10.5078.0", min_version:'7.0.0.0', path:path + "ADDINS", bulletin:bulletin, kb:"2920748")) vuln++;
    }
  }

  # Office 2007 SP3
  if (office_ver['12.0'])
  {
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      if (hotfix_is_vulnerable(file:"msosec.dll", version:"7.10.5078.0", min_version:'7.0.0.0', path:path + "ADDINS", bulletin:bulletin, kb:"2920795")) vuln++;
    }
  }
}

if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
