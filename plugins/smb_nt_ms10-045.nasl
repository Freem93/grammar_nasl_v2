#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(47713);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2010-0266");
  script_bugtraq_id(41446);
  script_osvdb_id(66296);
  script_xref(name:"IAVA", value:"2010-A-0093");
  script_xref(name:"MSFT", value:"MS10-045");

  script_name(english:"MS10-045: Vulnerability in Microsoft Office Outlook Could Allow Remote Code Execution (978212)");
  script_summary(english:"Checks version of Outlook");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of Microsoft Office installed on the remote Windows host
has a code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Outlook component of Microsoft Office has a remote code execution
vulnerability.  Opening an attachment in a specially crafted email can
result in arbitrary code execution.

A remote attacker could exploit this by sending a user an email and
tricking them into opening a malicious attachment, resulting in code
execution."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-045");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Office XP, 2003 and
2007."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Outlook ATTACH_BY_REF_RESOLVE File Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("audit.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-045';
kbs = make_list("980371");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

vuln = 0;
share = '';
lastshare = '';
accessibleshare = FALSE;
office_dirs = get_kb_list_or_exit("SMB/Office/Outlook/*/Path");
foreach install (keys(office_dirs))
{
  office_ver = install - 'SMB/Office/Outlook/' - '/Path';
  office_dir = office_dirs[install];

  share = hotfix_path2share(path:office_dir);
  if (share != lastshare || !accessibleshare)
  {
    lastshare = share;
    if (!is_accessible_share(share:share))
    {
      accessibleshare = FALSE;
    }
    else accessibleshare = TRUE;
  }
  if (accessibleshare)
  {
    if (
      # Outlook XP
      ('10.0' >< office_ver &&
      hotfix_is_vulnerable(file:"Outlook.exe", version:"10.0.6863.0", path:office_dir, bulletin:bulletin, kb:'980371')) ||

      # Outlook 2003
      ('11.0' >< office_ver &&
      hotfix_is_vulnerable(file:"Outlook.exe", version:"11.0.8325.0", path:office_dir, bulletin:bulletin, kb:'980373')) ||

      # Outlook 2007
      ('12.0' >< office_ver &&
      hotfix_is_vulnerable(file:"Outlook.exe", version:"12.0.6535.5005", path:office_dir, bulletin:bulletin, kb:'980376'))
    )
    {
      vuln++;
    }
  }
}
if (vuln)
{
  set_kb_item(name:'SMB/Missing/MS10-045', value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
