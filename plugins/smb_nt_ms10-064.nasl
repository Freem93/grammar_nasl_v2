#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49222);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/07/11 14:12:52 $");

  script_cve_id("CVE-2010-2728");
  script_bugtraq_id(43063);
  script_osvdb_id(67982);
  script_xref(name:"MSFT", value:"MS10-064");

  script_name(english:"MS10-064: Vulnerability in Microsoft Office Outlook Could Allow Remote Code Execution (978212)");
  script_summary(english:"Checks version of Contab32.dll");

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
vulnerability.  It is possible for a remote attacker to execute
arbitrary code if a user opens or previews a specially crafted email
in an affected version of Outlook that is connected to an Exchange
server with Online Mode."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-064");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Office 2002, 2003 and
2007."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
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

bulletin = 'MS10-064';
kbs = make_list("2293422");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


office_dir_xp = hotfix_get_programfilesdir() + "\Common Files\System\MAPI\1033";
office_dir_2k3 = hotfix_get_programfilesdir() + "\Common Files\System\MSMAPI\1033";
office_dir_2k7 = get_kb_item_or_exit('SMB/Office/Outlook/12.0/Path');
office_vers = hotfix_check_office_version();
if (isnull(office_vers)) exit(1, 'Error reading Office version from the KB.');

get_kb_item_or_exit('SMB/WindowsVersion');
share = '';
lastshare = '';
accessibleshare = TRUE;

share = hotfix_path2share(path:office_dir_xp);
lastshare = share;
if (is_accessible_share(share:share))
{
  accessibleshare = TRUE;
  if (
    # Outlook 2002
    (office_vers['10.0'] &&
    hotfix_is_vulnerable(file:"Contab32.dll", version:"10.0.6785.0", path:office_dir_xp, bulletin:bulletin, kb:'2293422')) ||

    # Outlook 2003
    (office_vers['11.0'] &&
    hotfix_is_vulnerable(file:"Contab32.dll", version:"11.0.8307.0", path:office_dir_2k3, bulletin:bulletin, kb:'2293428'))
  )
  {
    vuln++;
  }
}
share = hotfix_path2share(path:office_dir_2k7);
if (share != lastshare)
{
  NetUseDel(close:FALSE);
  accessibleshare = is_accessible_share(share:share);
}
if (accessibleshare)
{
  if (
    # Outlook 2007
    (office_vers['12.0'] &&
    hotfix_is_vulnerable(file:"Outlook.exe", version:"12.0.6539.5000", path:office_dir_2k7, bulletin:bulletin, kb:'2288953'))
  )
  {
    vuln++;
  }
}

if (vuln)
{
  set_kb_item(name:'SMB/Missing/MS10-064', value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
