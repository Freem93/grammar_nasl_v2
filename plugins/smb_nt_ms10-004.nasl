#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44414);
  script_version("$Revision: 1.33 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2010-0029", "CVE-2010-0030", "CVE-2010-0031", "CVE-2010-0032", "CVE-2010-0033", "CVE-2010-0034");
  script_bugtraq_id(38099, 38101, 38103, 38104, 38107, 38108);
  script_osvdb_id(62236, 62237, 62238, 62239, 62240, 62241);
  script_xref(name:"MSFT", value:"MS10-004");

  script_name(english:"MS10-004: Vulnerabilities in Microsoft Office PowerPoint Could Allow Remote Code Execution (975416)");
  script_summary(english:"Checks version of PowerPoint");

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
that is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted PowerPoint file, these issues could be leveraged to
execute arbitrary code subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-004");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for PowerPoint 2002 and
2003."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS10-004 Microsoft PowerPoint Viewer TextBytesAtom Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(94, 119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_ports(139, 445, 'Host/patch_management_checks');
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");

  exit(0);
}


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("audit.inc");
include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-004';
kbs = make_list("973143", "976881");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


vuln = 0;
installs = get_kb_list_or_exit("SMB/Office/PowerPoint/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/PowerPoint/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = "n/a";

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    if (ver[0] == 11 || ver[0] == 10)
    {
      # PowerPoint 2003.
      if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8318)
      {
        office_sp = get_kb_item("SMB/Office/2003/SP");
        if (!isnull(office_sp) && office_sp == 3)
        {
          vuln++;
          kb = "976881";
          info =
            '\n  Product           : PowerPoint 2003' +
            '\n  File              : ' + path +
            '\n  Installed version : ' + version +
            '\n  Fixed version     : 11.0.8318.0\n';
          hotfix_add_report(info, bulletin:bulletin, kb:kb);
        }
      }
      # PowerPoint 2002.
      else if (ver[0] == 10 && ver[1] == 0 && ver[2] < 6858)
      {
        office_sp = get_kb_item("SMB/Office/XP/SP");
        if (!isnull(office_sp) && office_sp == 3)
        {
          vuln++;
          kb = "973143";
          info =
            '\n  Product           : PowerPoint 2002' +
            '\n  File              : ' + path +
            '\n  Installed version : ' + version +
            '\n  Fixed version     : 10.0.6858.0\n';
          hotfix_add_report(info, bulletin:bulletin, kb:kb);
        }
      }
    }
  }
}
if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
