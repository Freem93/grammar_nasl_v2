#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50529);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/07/11 14:12:52 $");

  script_cve_id("CVE-2010-2572", "CVE-2010-2573");
  script_bugtraq_id(44626, 44628);
  script_osvdb_id(69090, 69091);
  script_xref(name:"MSFT", value:"MS10-088");

  script_name(english:"MS10-088: Vulnerabilities in Microsoft PowerPoint Could Allow Remote Code Execution (2293386)");
  script_summary(english:"Checks version of Pp7x32.dll, PowerPoint, or PowerPoint Viewer");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through Microsoft
PowerPoint."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is running a version of Microsoft PowerPoint
that is affected by several vulnerabilities :

  - A buffer overflow exists in the way the application
    parses the PowerPoint file format, which can be abused
    to execute arbitrary code if an attacker can trick a
    user into opening a specially crafted PowerPoint 95
    file using the affected application. Note that by
    default opening of such files is blocked in Microsoft
    PowerPoint 2003 Service Pack 3. (CVE-2010-2572)

  - An integer underflow exists in the way the application
    parses the PowerPoint file format, which could lead to
    heap corruption and allow for arbitrary code execution
    when opening a specially crafted PowerPoint file.
    (CVE-2010-2573)"
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-088");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for PowerPoint 2002 and
2003 as well as PowerPoint Viewer 2007."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint_viewer");
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
include("misc_func.inc");
include("audit.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-088';
kbs = make_list("2413272", "2413304", "2413381");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


vuln = FALSE;

installs = get_kb_list("SMB/Office/PowerPoint/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/PowerPoint/' - '/ProductPath';
    path = installs[install];

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    if (isnull(path)) path = "n/a";
    else path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+\\.exe$', replace:"\1", string:path, icase:TRUE);

    if (ver[0] == 11 || ver[0] == 10)
    {
      # PowerPoint 2003.
      if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8324)
      {
        office_sp = get_kb_item("SMB/Office/2003/SP");
        if (!isnull(office_sp) && office_sp == 3)
        {
          info =
            '\n  Product           : PowerPoint 2003' +
            '\n  Path              : ' + path +
            '\n  Installed version : ' + version +
            '\n  Fixed version     : 11.0.8324.0\n';
          hotfix_add_report(info, bulletin:bulletin, kb:"2413304");

          vuln = TRUE;
        }
      }
      # PowerPoint 2002.
      else if (ver[0] == 10 && ver[1] == 0 && ver[2] <= 6858)
      {
        office_sp = get_kb_item("SMB/Office/XP/SP");
        if (!isnull(office_sp) && office_sp == 3)
        {
          if (path != 'n/a')
          {
            if (hotfix_is_vulnerable(file:"Pp7x32.dll", version:"10.0.6867.0", min_version:'10.0.0.0', path:path, dir:"Xlators", bulletin:bulletin, kb:"2413272"))
              vuln = TRUE;
          }
        }
      }
    }
  }
}

# PowerPoint Viewer.
installs = get_kb_list("SMB/Office/PowerPointViewer/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/PowerPointViewer/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = "n/a";
    else path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+\\.exe$', replace:"\1", string:path, icase:TRUE);

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # PowerPoint Viewer 2007.
    if (
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6545 ||
        (ver[2] == 6545 && ver[3] < 5004)
      )
    )
    {
      info =
        '\n  Product           : PowerPoint Viewer 2007' +
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6545.5004\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2413381");

      vuln = TRUE;
      break;
    }
  }
}

if (vuln)
{
  set_kb_item(name:"SMB/Missing/MS10-088", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
