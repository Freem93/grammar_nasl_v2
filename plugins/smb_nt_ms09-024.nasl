#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39346);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/01/28 22:37:17 $");

  script_cve_id("CVE-2009-1533");
  script_bugtraq_id(35184);
  script_osvdb_id(54939);
  script_xref(name:"IAVB", value:"2009-B-0025");
  script_xref(name:"MSFT", value:"MS09-024");

  script_name(english:"MS09-024: Vulnerability in Microsoft Works Converters Could Allow Remote Code Execution (957632)");
  script_summary(english:"Checks file version of the converters");

  script_set_attribute(  attribute:"synopsis",  value:
"Arbitrary code can be executed on the remote host through Microsoft
Office.");
  script_set_attribute(  attribute:"description",   value:
"The remote host is running a version of Microsoft Works for Windows
document converters that is affected by a buffer overflow
vulnerability.  If an attacker can trick a user on the affected host
into opening a specially crafted Works file, this issue could be
leveraged to run arbitrary code on the host subject to the user's
privileges.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-024");
  script_set_attribute(  attribute:"solution",  value:
"Microsoft has released a set of patches for Office 2000, 2003 and XP
as well as 2007 Microsoft Office System, Works 8.5 and Works 9.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:works");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS09-024';
kbs = make_list("967044", "969559");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");

commonfiles = hotfix_get_officecommonfilesdir();
if  (!commonfiles) exit(1, "Error getting Office Common Files directory.");

office_versions = hotfix_check_office_version();

vuln = FALSE;
checkedfiles = make_array();
foreach ver (keys(office_versions))
{
  if (ver == '9.0' || ver == '10.0' || ver == '11.0' || ver == '12.0')
  {
    if (typeof(commonfiles) == 'array') path = commonfiles[ver] + "\Microsoft Shared\TextConv";
    else path = commonfiles + "\Microsoft Shared\TextConv";
    share = hotfix_path2share(path:path);
    # Office 2007
    if (ver == "12.0")
    {
      file = path + "\Works623.cnv";
      if (!checkedfiles[file])
      {
        if (hotfix_check_fversion(file:"Works632.cnv", version:"9.07.0613.0", path:path, bulletin:bulletin, kb:"969559") == HCF_OLDER) vuln = TRUE;
        checkedfiles[file] = 1;
      }
    }
    # Office 2003
    else if (ver == "11.0")
    {
      file1 = path + "\Wkcvqd01.dll";
      file2 = path + "\Wkcvqr01.dll";
      if (!checkedfiles[file1] && !checkedfiles[file2])
      {
        # Office 2003 is only vulnerable if Works 6-9 converter is installed
        # (vanilla install = version 9.7.621.0)
        if
        (
          hotfix_check_fversion(file:"Wkcvqd01.dll", version:"9.8.1117.0", min_version:"9.7.621.0", path:path, bulletin:bulletin, kb:"968326") == HCF_OLDER ||
          hotfix_check_fversion(file:"Wkcvqr01.dll", version:"9.8.1117.0", min_version:"9.7.621.0", path:path, bulletin:bulletin, kb:"968326") == HCF_OLDER
        ) vuln = TRUE;
        checkedfiles[file1] = 1;
        checkedfiles[file2] = 1;
      }
    }
    # Office XP.
    else if (ver == "10.0")
    {
      file = path + "\Works432.cnv";
      if (!checkedfiles[file])
      {
        if (hotfix_check_fversion(file:"Works432.cnv", version:"2008.9.808.0", path:path, bulletin:bulletin, kb:"957646") == HCF_OLDER) vuln = TRUE;
        checkedfiles[file] = 1;
      }
    }
    # Office 2000.
    else if (ver == "9.0")
    {
      file = path + "\Works432.cnv";
      if (!checkedfiles[file])
      {
        if (hotfix_check_fversion(file:"Works432.cnv", version:"2008.9.808.0", path:path, bulletin:bulletin, kb:"957646") == HCF_OLDER) vuln = TRUE;
        checkedfiles[file] = 1;
      }
    }
  }
}

if (hotfix_check_works_installed())
{
  if (
    # Works 9.
    hotfix_check_fversion(file:"Wkcvqd01.dll", version:"9.8.1117.0", min_version:"9.0.0.0", path:path, bulletin:bulletin, kb:"967044") == HCF_OLDER ||
    hotfix_check_fversion(file:"Wkcvqr01.dll", version:"9.8.1117.0", min_version:"9.0.0.0", path:path, bulletin:bulletin, kb:"967044") == HCF_OLDER ||

    # Works 8.
    hotfix_check_fversion(file:"Wkcvqd01.dll", version:"8.7.216.0", min_version:"8.0.0.0", path:path, bulletin:bulletin, kb:"967043") == HCF_OLDER ||
    hotfix_check_fversion(file:"Wkcvqr01.dll", version:"8.7.216.0", min_version:"8.0.0.0", path:path, bulletin:bulletin, kb:"967043") == HCF_OLDER
  )
  {
    vuln = TRUE;
  }
}
if (vuln)
{
  set_kb_item(name:"SMB/Missing/MS09-024", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
