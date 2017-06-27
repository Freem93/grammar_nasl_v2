#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(69828);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/04/23 21:44:06 $");

  script_cve_id("CVE-2013-3870");
  script_bugtraq_id(62188);
  script_osvdb_id(97110);
  script_xref(name:"MSFT", value:"MS13-068");

  script_name(english:"MS13-068: Vulnerability in Microsoft Outlook Could Allow Remote Code Execution (2756473)");
  script_summary(english:"Checks version of Outlook.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of Microsoft Office installed on the remote Windows is
affected by a code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Outlook component of Microsoft Office is affected by a remote code
execution vulnerability due to a flaw in how Outlook parses S/MIME
messages.  It is possible for a remote attacker to execute arbitrary
code if a user opens or previews a specially crafted email in an
affected version of Outlook."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS13-068");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office 2007 and 2010.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2007");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2010");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS13-068';
kbs = make_list(
  "2825999",  # Office 2007
  "2794707"   # Office 2010
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

office_versions = hotfix_check_office_version();

outlook_2k7_path = get_kb_item("SMB/Office/Outlook/12.0/Path");
outlook_2k10_path = get_kb_item("SMB/Office/Outlook/14.0/Path");

vuln = 0;

# Office 2007 SP3
if (!isnull(outlook_2k7_path) && office_versions["12.0"])
{
  office_sp = get_kb_item("SMB/Office/2007/SP");
  if (!isnull(office_sp) && office_sp == 3)
  {
    if (hotfix_is_vulnerable(file:"Outlook.exe", version:"12.0.6680.5000", min_version:"12.0.0.0", path:outlook_2k7_path, bulletin:bulletin, kb:'2825999')) vuln++;
    NetUseDel(close:FALSE);
  }
}

# Office 2010 SP1 & SP2
if (!isnull(outlook_2k10_path) && office_versions["14.0"])
{
  office_sp = get_kb_item("SMB/Office/2010/SP");
  if (!isnull(office_sp) && (office_sp == 1 || office_sp == 2))
  {
    if (hotfix_is_vulnerable(file:"Outlook.exe", version:"14.0.7105.5000", min_version:"14.0.0.0", path:outlook_2k10_path, bulletin:bulletin, kb:'2794707')) vuln++;
    NetUseDel(close:FALSE);
  }
}

if (vuln)
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
