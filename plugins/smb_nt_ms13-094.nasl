#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(70852);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/04/23 21:44:06 $");

  script_cve_id("CVE-2013-3905");
  script_bugtraq_id(63603);
  script_osvdb_id(99653);
  script_xref(name:"MSFT", value:"MS13-094");
  script_xref(name:"IAVA", value:"2013-A-0216");

  script_name(english:"MS13-094: Vulnerability in Microsoft Outlook Could Allow Information Disclosure (2894514)");
  script_summary(english:"Checks version of Outlook.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of Microsoft Outlook installed on the remote Windows host
is affected by an information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Outlook component of Microsoft Office is affected by an information
disclosure vulnerability due to a flaw in how Outlook parses S/MIME
messages.  It is possible for a remote attacker to exploit the
vulnerability if a user opens or previews a specially crafted email in
an affected version of Outlook."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS13-094");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2007, 2010, 2013 and
2013 RT.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2007");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2010");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2013");

  script_set_attribute(attribute:"stig_severity", value:"II");
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
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS13-094';
kbs = make_list(
  "2825644",  # Office 2007
  "2837597",  # Office 2010
  "2837618"   # Office 2013
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

office_versions = hotfix_check_office_version();

outlook_2k7_path = get_kb_item("SMB/Office/Outlook/12.0/Path");
outlook_2k10_path = get_kb_item("SMB/Office/Outlook/14.0/Path");
outlook_2k13_path = get_kb_item("SMB/Office/Outlook/15.0/Path");

vuln = 0;

# Office 2007 SP3
if (!isnull(outlook_2k7_path) && office_versions["12.0"])
{
  office_sp = get_kb_item("SMB/Office/2007/SP");
  if (!isnull(office_sp) && office_sp == 3)
  {
    if (hotfix_is_vulnerable(file:"Exsec32.dll", version:"12.0.6685.5000", min_version:"12.0.0.0", path:outlook_2k7_path, bulletin:bulletin, kb:'2825644')) vuln++;
    NetUseDel(close:FALSE);
  }
}

# Office 2010 SP1 & SP2
if (!isnull(outlook_2k10_path) && office_versions["14.0"])
{
  office_sp = get_kb_item("SMB/Office/2010/SP");
  if (!isnull(office_sp) && (office_sp == 1 || office_sp == 2))
  {
    if (hotfix_is_vulnerable(file:"Outlook.exe", version:"14.0.7109.5000", min_version:"14.0.0.0", path:outlook_2k10_path, bulletin:bulletin, kb:'2837597')) vuln++;
    NetUseDel(close:FALSE);
  }
}

# Office 2013
if (!isnull(outlook_2k13_path) && office_versions["15.0"])
{
  if (hotfix_is_vulnerable(file:"Outlook.exe", version:"15.0.4551.1004", min_version:"15.0.0.0", path:outlook_2k13_path, bulletin:bulletin, kb:'2837618')) vuln++;
  NetUseDel(close:FALSE);
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
