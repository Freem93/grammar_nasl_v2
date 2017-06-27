#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79129);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2014-6333", "CVE-2014-6334", "CVE-2014-6335");
  script_bugtraq_id(70961, 70962, 70963);
  script_osvdb_id(114524, 114527, 114528);
  script_xref(name:"MSFT", value:"MS14-069");

  script_name(english:"MS14-069: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (3009710)");
  script_summary(english:"Checks Word / Office version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of Microsoft Office, Office
Compatibility Pack, or Microsoft Word Viewer that is affected by one
or more vulnerabilities :

  - A double delete remote code execution vulnerability due
    to Microsoft Word not properly handling objects in
    memory while parsing specially crafted Office files. An
    attacker can exploit this vulnerability by convincing or
    tricking a user into opening a specially crafted file,
    resulting in execution of arbitrary code in the context
    of the current user. (CVE-2014-6333)

  - A bad index remote code execution vulnerability due to
    Microsoft Word not properly handling objects in memory
    while parsing specially crafted Office files. An
    attacker can exploit this vulnerability by convincing or
    tricking a user into opening a specially crafted file,
    resulting in execution of arbitrary code in the context
    of the current user. (CVE-2014-6334)

  - An invalid pointer remote code execution vulnerability
    due to Microsoft Word not properly handling objects in
    memory while parsing specially crafted Office files. An
    attacker can exploit this vulnerability by convincing or
    tricking a user into opening a specially crafted file,
    resulting in execution of arbitrary code in the context
    of the current user. (CVE-2014-6335)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-069");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2007, Office
Compatibility Pack, and Microsoft Word Viewer.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

global_var bulletin, vuln;

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS14-069';
kbs = make_list(
  2899526, # Office Compatibility Pack
  2899527, # Word 2007
  2899553  # Microsoft Word Viewer
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, "Failed to determine the location of %windir%.");

# Word
installs = get_kb_list("SMB/Office/Word/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/Word/' - '/ProductPath';
    path = installs[install];
    info = "";

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # Word 2007 SP3
    if (
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6707 ||
        (ver[2] == 6707 && ver[3] < 5000)
      )
    )
    {
      office_sp = get_kb_item("SMB/Office/2007/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        info =
          '\n  Product           : Word 2007 SP3' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 12.0.6707.5000' + '\n';
        kb = "2899527";
      }
    }

    if (info)
    {
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
      vuln = TRUE;
    }
  }
}

# Word Viewer
installs = get_kb_list("SMB/Office/WordViewer/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    info = "";
    version = install - 'SMB/Office/WordViewer/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = "n/a";

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8413)
    {
      info =
        '\n  Product           : Word Viewer' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 11.0.8413.0' + '\n';
      kb = "2899553";
    }

    if (info)
    {
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
      vuln = TRUE;
      break;
    }
  }
}

# Compatibility pack
version = '';
installs = get_kb_list("SMB/Office/WordCnv/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/WordCnv/' - '/ProductPath';
    path = installs[install];

    if (!isnull(path))
    {
      share = hotfix_path2share(path:path);
      if (!is_accessible_share(share:share))
        audit(AUDIT_SHARE_FAIL, share);

      path = path - '\\Wordconv.exe';

      old_report = hotfix_get_report();
      check_file = "wordcnv.dll";

      if (hotfix_check_fversion(path:path, file:check_file, version:"12.0.6707.5000", min_version:"12.0.0.0") == HCF_OLDER)
      {
        file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + check_file);
        kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
        kb_name = ereg_replace(pattern:"//"+check_file, replace:"/"+check_file, string:kb_name);
        version = get_kb_item(kb_name);

        info =
          '\n  Product           : Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats' +
          '\n  File              : ' + path + '\\' + check_file +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 12.0.6707.5000' + '\n';
        hcf_report = '';
        hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2899526");
        vuln = TRUE;
      }
    }
  }
}

if (!version)
{
  # Additional check if registry key is missing
  path = hotfix_get_officecommonfilesdir(officever:"12.0") + "\Microsoft Office\Office12";

  kb = "2899526";
  if (
    hotfix_is_vulnerable(file:"wordcnv.dll", version:"12.0.6707.5000", min_version:"12.0.0.0", path:path, bulletin:bulletin, kb:kb)
  ) vuln = TRUE;
}

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
