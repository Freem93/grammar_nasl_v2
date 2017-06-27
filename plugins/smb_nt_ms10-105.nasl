#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51177);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/06/30 19:55:38 $");

  script_cve_id("CVE-2010-3945", "CVE-2010-3946", "CVE-2010-3947", "CVE-2010-3949",
                "CVE-2010-3950", "CVE-2010-3951", "CVE-2010-3952");
  script_bugtraq_id(45270, 45273, 45274, 45275, 45278, 45283, 45285);
  script_osvdb_id(69803, 69804, 69805, 69806, 69807, 69808, 69809);
  script_xref(name:"MSFT", value:"MS10-105");

  script_name(english:"MS10-105: Vulnerabilities in Microsoft Office Graphics Filters Could Allow for Remote Code Execution (968095)");
  script_summary(english:"Checks Office version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through the
Microsoft Office filters."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of Microsoft Office with
multiple memory corruption vulnerabilities.

A remote attacker could exploit this by tricking a user into viewing a
specially crafted image file with Office, resulting in arbitrary code
execution."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-105");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Office XP, 2003, 2007,
2010, and Office Converter Pack."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_converter_pack");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:works");
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
include("audit.inc");

include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-105';
kbs = make_list("2289078");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

common = hotfix_get_officecommonfilesdir();
if (isnull(common)) exit(1, 'hotfix_get_officecommonfilesdir() failed.');

office_vers = hotfix_check_office_version();

vuln = FALSE;
checkedfiles = make_array();
if (office_vers)
{
  foreach ver (keys(office_vers))
  {
    if (typeof(common) == 'array')  dir = common[ver];
    else  dir = common;
    if (ver == "10.0" || ver == "11.0" || ver == "12.0" || ver == "14.0")
    {
      share = hotfix_path2share(path:dir);
      if (is_accessible_share(share:share))
      {
        # Office 2010
        if (ver == "14.0")
        {
          file = dir + '\\Microsoft Shared\\TextConv\\Msconv97.dll';
          if (!checkedfiles[file])
          {
            if (hotfix_is_vulnerable(path:dir + '\\Microsoft Shared\\TextConv', file:"Msconv97.dll", version:"2010.1400.5114.5004", min_version:"2010.0.0.0", bulletin:bulletin, kb:'2289078')) vuln = TRUE;
            checkedfiles[file] = 1;
          }
        }
        # Office 2007
        else if (ver == "12.0")
        {
          file = dir + '\\Microsoft Shared\\TextConv\\Msconv97.dll';
          if (!checkedfiles[file])
          {
            if (office_vers["12.0"] && hotfix_is_vulnerable(path:dir + '\\Microsoft Shared\\TextConv', file:"Msconv97.dll", version:"2006.1200.6539.5004", min_version:"2006.0.0.0", bulletin:bulletin, kb:'2289078')) vuln = TRUE;
            checkedfiles[file] = 1;
          }
        }
        # Office XP, 2003, and File Converter Pack
        else if (ver == "10.0")
        {
          file = dir + '\\Microsoft Shared\\Grphflt\\Png32.flt';
          if (!checkedfiles[file])
          {
            if (office_vers["10.0"] && hotfix_is_vulnerable(path:dir + '\\Microsoft Shared\\Grphflt', file:"Png32.flt", version:"2003.1100.8329.0", min_version:"2003.0.0.0", bulletin:bulletin, kb:'2289162')) vuln = TRUE;
            checkedfiles[file] = 1;
          }
        }
        else if (ver == "11.0")
        {
          file = dir + '\\Microsoft Shared\\Grphflt\\Png32.flt';
          if (!checkedfiles[file])
          {
            if (office_vers["11.0"] && hotfix_is_vulnerable(path:dir + '\\Microsoft Shared\\Grphflt', file:"Png32.flt", version:"2003.1100.8329.0", min_version:"2003.0.0.0", bulletin:bulletin, kb:'2289163')) vuln = TRUE;
            checkedfiles[file] = 1;
          }
        }
      }
    }
  }
}
else
{
  if (typeof(common) != 'array')
  {
    dir = common;
    share = hotfix_path2share(path:dir);
    if (is_accessible_share(share:share))
    {
      if (hotfix_is_vulnerable(path:dir + '\\Microsoft Shared\\Grphflt', file:"Png32.flt", version:"2003.1100.8329.0", min_version:"2003.0.0.0", bulletin:bulletin, kb:'2456849'))
      {
        vuln = TRUE;
      }
    }
  }
  else
  {
    foreach ver (keys(common))
    {
      dir = common[ver];
      share = hotfix_path2share(path:dir);
      if (is_accessible_share(share:share))
      {
        if (hotfix_is_vulnerable(path:dir + '\\Microsoft Shared\\Grphflt', file:"Png32.flt", version:"2003.1100.8329.0", min_version:"2003.0.0.0", bulletin:bulletin, kb:'2456849'))
        {
          vuln = TRUE;
          break;
        }
      }
    }
  }
}
if (vuln)
{
  set_kb_item(name:'SMB/Missing/MS10-105', value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
