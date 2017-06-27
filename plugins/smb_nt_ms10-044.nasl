#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(47712);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/07/07 15:05:40 $");

  script_cve_id("CVE-2010-0814", "CVE-2010-1881");
  script_bugtraq_id(41442, 41444);
  script_osvdb_id(66294, 66295);
  script_xref(name:"MSFT", value:"MS10-044");
  script_xref(name:"IAVA", value:"2010-A-0094");

  script_name(english:"MS10-044: Vulnerabilities in Microsoft Office Access ActiveX Controls Could Allow Remote Code Execution (982335)");
  script_summary(english:"Checks version of Msaccess.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of Microsoft Office on the remote Windows host has
multiple code execution vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Access component of Microsoft Office has one or more vulnerable
ActiveX controls installed.  An attacker could exploit these issues by
tricking a user into requesting a malicious web page, resulting in
arbitrary code execution."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-044");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office 2003 and 2007.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:access");
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

bulletin = 'MS10-044';
kbs = make_list("981716");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

access_dirs = get_kb_list_or_exit("SMB/Office/Access/*/Path");

get_kb_item_or_exit('SMB/WindowsVersion');

share = '';
lastshare = '';
accessibleshare = FALSE;
foreach install (keys(access_dirs))
{
  access_ver = install - 'SMB/Office/Access/' - '/Path';
  access_dir = access_dirs[install];
  share = hotfix_path2share(path:access_dir);
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
      # Outlook 2003
      (
        '11.0' >< access_ver &&
        hotfix_is_vulnerable(file:"Msaccess.exe", version:"11.0.8321.0", min_version:"11.0.0.0", path:access_dir, bulletin:bulletin, kb:"981716")
      ) ||

      # Outlook 2007
      (
        '12.0' >< access_ver &&
        hotfix_is_vulnerable(file:"Msaccess.exe", version:"12.0.6535.5005", min_version:"12.0.0.0", path:access_dir, bulletin:bulletin, kb:"979440")
      )
    )
    {
      vuln++;
    }
  }
}
hotfix_check_fversion_end();
if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
