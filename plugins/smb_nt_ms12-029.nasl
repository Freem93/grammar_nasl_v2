#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59037);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/03 21:08:35 $");

  script_cve_id("CVE-2012-0183");
  script_bugtraq_id(53344);
  script_osvdb_id(81732);
  script_xref(name:"MSFT", value:"MS12-029");

  script_name(english:"MS12-029: Vulnerability in Microsoft Word Could Allow Remote Code Execution (2680352)");
  script_summary(english:"Checks file versions");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A Microsoft Office component installed on the remote host has a memory
corruption vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Office and/or Office Compatibility Pack installed on
the remote host has a memory corruption vulnerability.  A remote
attacker could exploit this by tricking a user into opening a
specially crafted RTF file, resulting in arbitrary code execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-186/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Nov/112");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS12-029");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Office 2003, 2007, and
Office Compatibility Pack."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS12-029';
kbs = make_list('2596880', '2596917', '2598332');
if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

kb = "";
vuln = FALSE;
# Word.
installs = get_kb_list("SMB/Office/Word/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    info = "";
    version = install - 'SMB/Office/Word/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = 'n/a';

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

    # Word 2007
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (
      (!isnull(office_sp) && (office_sp == 2 || office_sp == 3)) &&
      (
        ver[0] == 12 && ver[1] == 0 &&
        (
          ver[2] < 6661 ||
          (ver[2] == 6661 && ver[3] < 5000)
        )
      )
    )
    {
      info =
        '\n  Product           : Word 2007' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6661.5000' + '\n';
      kb = "2596917";
    }

    # Word 2003
    office_sp = get_kb_item("SMB/Office/2003/SP");
    if ((!isnull(office_sp) && (office_sp == 3)) && (ver[0] == 11 && ver[1] == 0 && ver[2] < 8345))
    {
        info =
          '\n  Product           : Word 2003' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 11.0.8345.0' + '\n';
        kb = "2598332";
    }

    if (info)
    {
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
      vuln = TRUE;
    }
  }
}

# 2007 Microsoft Office system and the Microsoft Office Compatibility Pack.
installs = get_kb_list("SMB/Office/WordCnv/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/WordCnv/' - '/ProductPath';
    path = installs[install];

    if (path)
    {
      share = hotfix_path2share(path:path);
      if (is_accessible_share(share:share))
      {
        path = path - '\\Wordconv.exe';

        old_report = hotfix_get_report();
        check_file = "wordcnv.dll";

        if (version =~ '^12\\.0' && hotfix_check_fversion(path:path, file:check_file, version:"12.0.6661.5000") == HCF_OLDER)
        {
          file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + check_file);
          kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
          version = get_kb_item(kb_name);

          info =
            '\n  Product           : Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats' +
            '\n  File              : ' + path + '\\' + check_file +
            '\n  Installed version : ' + version +
            '\n  Fixed version     : 12.0.6661.5000' + '\n';

          hcf_report = '';
         hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2596880");
          vuln = TRUE;
        }
      }
    }
  }
  hotfix_check_fversion_end();
}

if (vuln)
{
  set_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else
{
  audit(AUDIT_HOST_NOT, 'affected');
}

