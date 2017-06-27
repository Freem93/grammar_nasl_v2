#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71321);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/01/28 22:37:18 $");

  script_cve_id("CVE-2013-5057");
  script_bugtraq_id(64095);
  script_osvdb_id(100764);
  script_xref(name:"MSFT", value:"MS13-106");
  script_xref(name:"IAVB", value:"2013-B-0135");

  script_name(english:"MS13-106: Vulnerability in a Microsoft Office Shared Component Could Allow Security Feature Bypass (2905238)");
  script_summary(english:"Checks version of hxds.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host is affected by a security feature bypass
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is running a version of Microsoft Office that
contains a shared component that is affected by a security feature
bypass.  Successful exploitation of the issue can allow an attacker to
bypass the Address Space Layout Randomization (ASLR) security feature. 
An attacker would need to entice a victim to visit a specially crafted
web page with a browser capable of instantiating COM components in order
to trigger the issue."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-106");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Microsoft Office 2007 and
2010."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS13-106';
kbs = make_list(2850016, 2850022);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

office_ver = hotfix_check_office_version();
vuln = 0;

# Office 2010 SP1 or SP2
if (office_ver['14.0'])
{
  office_sp = get_kb_item("SMB/Office/2010/SP");
  if (!isnull(office_sp) && (office_sp == 1 || office_sp == 2))
  {
    path = hotfix_get_officecommonfilesdir(officever:"14.0") + "\Microsoft Shared\Help";

    if (hotfix_is_vulnerable(file:"hxds.dll", version:"5.70.51021.0", path:path, bulletin:bulletin, kb:"2850016")) vuln++;
  }
}

# Office 2007 SP3
if (office_ver['12.0'])
{
  office_sp = get_kb_item("SMB/Office/2007/SP");
  if (!isnull(office_sp) && office_sp == 3)
  {
    path = hotfix_get_officecommonfilesdir(officever:"12.0") + "\Microsoft Shared\Help";

    if (hotfix_is_vulnerable(file:"hxds.dll", version:"5.70.51021.0", path:path, bulletin:bulletin, kb:"2850022")) vuln++;
  }
}

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
  audit(AUDIT_HOST_NOT, 'affected');
}
