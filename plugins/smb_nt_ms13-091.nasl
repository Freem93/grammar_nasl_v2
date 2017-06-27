#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70849);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/01/28 22:37:18 $");

  script_cve_id("CVE-2013-0082", "CVE-2013-1324", "CVE-2013-1325");
  script_bugtraq_id(63559, 63569, 63570);
  script_osvdb_id(99648, 99650, 99651);
  script_xref(name:"MSFT", value:"MS13-091");

  script_name(english:"MS13-091: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (2885093)");
  script_summary(english:"Checks file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office component installed on the remote host is
affected by multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of Microsoft Office or
Office Compatibility Pack that is affected by multiple remote code
execution vulnerabilities while parsing WordPerfect document files.

If an attacker can trick a user on the affected host into opening a
specially crafted file, it may be possible to leverage these issues to
read arbitrary files on the target system or execute arbitrary code,
subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-091");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2003, 2007, 2010,
2013, and Office Compatibility Pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

bulletin = "MS13-091";
kbs = make_list(
  2553284,
  2760415,
  2760494,
  2760781,
  2768005
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

info = "";
vuln = 0;
arch = get_kb_item_or_exit("SMB/ARCH");

######################################################################
# Office
######################################################################
# Ensure Office is installed
office_vers = hotfix_check_office_version();
commonfiles = hotfix_get_commonfilesdir();

if (!commonfiles) audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');

x64_path = hotfix_get_programfilesdirx86();
if (arch == 'x64' && !x64_path) audit(AUDIT_PATH_NOT_DETERMINED, 'Program Files (x86)');

#  Check file version
if (office_vers["14.0"])
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:commonfiles);
  if (is_accessible_share(share:share))
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 1)
    {
      path = get_kb_item('SMB/Office/Word/14.0/Path');
      if (!isnull(path))
      {
        path += "\Proof";
        old_report = hotfix_get_report();
        check_file = "mssp7en.dll";

        if (hotfix_check_fversion(path:path, file:check_file, version:"14.0.7107.5000", min_version:"14.0.6029.1000") == HCF_OLDER)
        {
          file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + check_file);
          kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
          version = get_kb_item(kb_name);

          info =
            '\n  Product           : Microsoft Office 2010' +
            '\n  File              : ' + path + '\\' + check_file +
            '\n  Installed version : ' + version +
            '\n  Fixed version     : 14.0.7107.5000' + '\n';

          hcf_report = '';
          hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2760781");
          vuln++;
        }
      }
    }
  }
}

# Office 2003 SP3
if (office_vers["11.0"])
{
  office_sp = get_kb_item("SMB/Office/2003/SP");
  if (!isnull(office_sp) && office_sp == 3)
  {
    kb = "2760494";
    if (
      hotfix_is_vulnerable(file:"Wpft532.cnv", version:"2003.1100.8405.0", min_version:"2003.1100.0.0", path:commonfiles+"\microsoft shared\TextConv", bulletin:bulletin, kb:kb) ||
      hotfix_is_vulnerable(file:"Wpft532.cnv", arch:"x64", version:"2003.1100.8405.0", min_version:"2003.1100.0.0", path:x64_path+"\microsoft shared\TextConv", bulletin:bulletin, kb:kb)
    ) vuln++;
  }
}

# Office 2007 SP3
if (office_vers["12.0"])
{
  office_sp = get_kb_item("SMB/Office/2007/SP");
  if (!isnull(office_sp) && office_sp == 3)
  {
    kb = "2760415";
    if (
      hotfix_is_vulnerable(file:"Wpft532.cnv", version:"2006.1200.6676.5000", min_version:"2006.1200.0.0", path:commonfiles+"\microsoft shared\TextConv", bulletin:bulletin, kb:kb) ||
      hotfix_is_vulnerable(file:"Wpft532.cnv", arch:"x64", version:"2006.1200.6676.5000", min_version:"2006.1200.0.0", path:x64_path+"\microsoft shared\TextConv", bulletin:bulletin, kb:kb)
    ) vuln++;
  }
}

# Office 2010 SP1
else if (office_vers["14.0"])
{
  office_sp = get_kb_item("SMB/Office/2010/SP");
  if (!isnull(office_sp) && office_sp == 1)
  {
    kb = "2553284";
    if (
      hotfix_is_vulnerable(file:"Wpft532.cnv", version:"2010.1400.7011.1000", min_version:"2010.1400.0.0", path:commonfiles+"\microsoft shared\TextConv", bulletin:bulletin, kb:kb) ||
      hotfix_is_vulnerable(file:"Wpft532.cnv", arch:"x64", version:"2010.1400.7011.1000", min_version:"2010.1400.0.0", path:x64_path+"\microsoft shared\TextConv", bulletin:bulletin, kb:kb)
    ) vuln++;
  }
}
# Office 2013
else if (office_vers["15.0"])
{
  office_sp = get_kb_item("SMB/Office/2013/SP");
  if (!isnull(office_sp) && office_sp == 0)
  {
    kb = "2768005";
    if (
      hotfix_is_vulnerable(file:"Wpft532.cnv", version:"2012.1500.4525.1000", min_version:"2012.1500.0.0", path:commonfiles+"\microsoft shared\TextConv", bulletin:bulletin, kb:kb) ||
      hotfix_is_vulnerable(file:"Wpft532.cnv", arch:"x64", version:"2012.1500.4525.1000", min_version:"2012.1500.0.0", path:x64_path+"\microsoft shared\TextConv", bulletin:bulletin, kb:kb)
    ) vuln++;
  }
}
if (info || vuln)
{
  set_kb_item(name:"SMB/Missing/" + bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, "affected");
}
