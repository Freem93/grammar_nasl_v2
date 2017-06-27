#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(46843);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/06/30 19:55:38 $");

  script_cve_id("CVE-2010-1263");
  script_bugtraq_id(40574);
  script_osvdb_id(65219);
  script_xref(name:"MSFT", value:"MS10-036");

  script_name(english:"MS10-036: Vulnerability in COM Validation in Microsoft Office Could Allow Remote Code Execution (983235)");
  script_summary(english:"Checks if Office version is up to date");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through opening a
Microsoft Office file.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a vulnerable version of Microsoft Office 2003
or 2007. Opening a specially crafted Office file can result in
arbitrary code execution. A remote attacker can exploit this by
tricking a user into opening a specially crafted Office file.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-036");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office 2003 and 2007.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:publisher");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS10-036';
kbs = make_list("982122", "982124", "982127", "982133", "982134", "982135", "982157", "982158", "982308", "982311", "982312");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


function is_vuln(ver, fix)
{
  local_var i;

  ver = split(ver, sep:'.', keep:FALSE);
  fix = split(fix, sep:'.', keep:FALSE);

  for (i = 0; i < max_index(ver); i++)
  {
    if (int(ver[i]) < int(fix[i]))
      return TRUE;
    if (int(ver[i]) > int(fix[i]))
      return FALSE;
  }

  return FALSE;
}

arch = get_kb_item_or_exit("SMB/ARCH");

if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");

x86_path = hotfix_get_commonfilesdir();
if (!x86_path) audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');
x64_path = hotfix_get_programfilesdirx86();
if (arch == 'x64' && !x64_path) audit(AUDIT_PATH_NOT_DETERMINED, 'Program Files (x86)');
vuln = 0;

office_vers = hotfix_check_office_version();

share = '';
lastshare = '';
accessibleshare = FALSE;
kb = '';
if (!isnull(office_vers))
{
  if (office_vers["11.0"])
  {
    # Office 2003
    share = hotfix_path2share(path:x86_path);
    lastshare = share;
    if (is_accessible_share(share:share))
    {
      accessibleshare = TRUE;

      if (
        hotfix_is_vulnerable(file:"Mso.dll", version:"11.0.8324.0", min_version:'11.0.0.0', path:x86_path+"\Microsoft Shared\Office11", bulletin:bulletin, kb:'982311') ||
        hotfix_is_vulnerable(file:"Mso.dll", arch:"x64", version:"11.0.8324.0", min_version:'11.0.0.0', path:x64_path+"\Common Files\Microsoft Shared\Office11", bulletin:bulletin, kb:'982311')
      ) vuln++;
    }
  }
  if (office_vers["12.0"])
  {
    # Office 2007
    share = hotfix_path2share(path:x86_path);
    if (lastshare != share || !accessibleshare)
    {
      lastshare = share;
      if (is_accessible_share(share:share))
      {
        accessibleshare = TRUE;
      }
    }

    if (
      (hotfix_is_vulnerable(file:"Mso.dll", version:"12.0.6535.5002", min_version:'12.0.0.0', path:x86_path+"\Microsoft Shared\Office12", bulletin:bulletin, kb:'982312')) ||
      (hotfix_is_vulnerable(file:"Mso.dll", arch:"x64", version:"12.0.6535.5002", min_version:'12.0.0.0', path:x64_path+"\Common Files\Microsoft Shared\Office12", bulletin:bulletin, kb:'982312'))
    ) vuln++;
  }
}

# Visio
installs = get_kb_list("SMB/Office/Visio/*/VisioPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/Visio/' - '/VisioPath';
    path = installs[install];
    share = hotfix_path2share(path:path);
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
        version &&
        ("12.0" >< version &&
        hotfix_is_vulnerable(path:path, file:"Vislib.dll", version:"12.0.6535.5002", bulletin:bulletin, kb:'982127')) ||
        ("11.0" >< version &&
        hotfix_is_vulnerable(path:path, file:"Visio11\Vislib.dll", version:"11.0.8323.0", bulletin:bulletin, kb:'982126'))
      )
      {
        vuln++;
      }
    }
  }
}
hotfix_check_fversion_end();

# Use the KB to check the other components

office_sp2003 = get_kb_item("SMB/Office/2003/SP");
office_sp2007 = get_kb_item("SMB/Office/2007/SP");
# Excel
installs = get_kb_list("SMB/Office/Excel/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/Excel/' - '/ProductPath';
    path = installs[install];

    if (
      version &&
      (
        ('11.0.' >< version && is_vuln(ver:version, fix:'11.0.8324.0') && (!isnull(office_sp2003) && office_sp2003 == 3)) ||
        ('12.0.' >< version && is_vuln(ver:version, fix:'12.0.6535.5002') && (!isnull(office_sp2007) && (office_sp2007 == 1 || office_sp2007 == 2)))
      )
    )
    {
      ver = split(version, sep:'.', keep:FALSE);
      if (ver[0] == '11')
      {
        fix = '11.0.8324.0';
        kb = '982133';
      }
      else
      {
        fix = '12.0.6535.5002';
        kb = '982308';
      }

      info =
        '\n  Product           : Excel' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix + '\n';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
      vuln++;
    }
  }
}

# Powerpoint
installs = get_kb_list("SMB/Office/PowerPoint/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/PowerPoint/' - '/ProductPath';
    path = installs[install];

    if (
      version &&
      (
        ('11.0.' >< version && is_vuln(ver:version, fix:'11.0.8324.0') && (!isnull(office_sp2003) && office_sp2003 == 3)) ||
        ('12.0.' >< version && is_vuln(ver:version, fix:'12.0.6500.5000') && (!isnull(office_sp2007) && (office_sp2007 == 1 || office_sp2007 == 2)))
      )
    )
    {
      ver = split(version, sep:'.', keep:FALSE);
      if (ver[0] == '11')
      {
        fix = '11.0.8324.0';
        kb = '982157';
      }
      else
      {
        fix = '12.0.6500.5000';
        kb = '982158';
      }

      info =
        '\n  Product           : PowerPoint'+
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix + '\n';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
      vuln++;
    }
  }
}

# Publisher
installs = get_kb_list("SMB/Office/Publisher/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/Publisher/' - '/ProductPath';
    path = installs[install];

    if (
      version &&
      (
        ('11.0.' >< version && is_vuln(ver:version, fix:'11.0.8324.0')) ||
        ('12.0.' >< version && is_vuln(ver:version, fix:'12.0.6535.5002'))
      )
    )
    {
      ver = split(version, sep:'.', keep:FALSE);
      if (ver[0] == '11')
      {
        fix = '11.0.8324.0';
        kb = '982122';
      }
      else
      {
        fix = '12.0.6535.5002';
        kb = '982124';
      }

      info =
        '\n  Product           : Publisher' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix + '\n';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
      vuln++;
    }
  }
}

# Word
installs = get_kb_list("SMB/Office/Word/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/Word/' - '/ProductPath';
    path = installs[install];

    if (
      version &&
      (
        ('11.0.' >< version && is_vuln(ver:version, fix:'11.0.8324.0') && (!isnull(office_sp2003) && office_sp2003 == 3)) ||
        ('12.0.' >< version && is_vuln(ver:version, fix:'12.0.6535.5000') && (!isnull(office_sp2007) && (office_sp2007 == 1 || office_sp2007 == 2)))
      )
    )
    {
      ver = split(version, sep:'.', keep:FALSE);
      if (ver[0] == '11')
      {
        fix = '11.0.8324.0';
        kb = '982134';
      }
      else
      {
        fix = '12.0.6535.5000';
        kb = '982135';
      }

      info =
        '\n  Product           : Word'+
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix + '\n';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
      vuln++;
    }
  }
}

if (vuln)
{
  set_kb_item(name:'SMB/Missing/MS10-036', value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
