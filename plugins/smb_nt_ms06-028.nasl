#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(21691);
 script_version("$Revision: 1.33 $");
 script_cvs_date("$Date: 2016/07/11 14:12:52 $");

 script_cve_id("CVE-2006-0022");
 script_bugtraq_id(18382);
 script_osvdb_id(26435);
 script_xref(name:"CERT", value:"190089");
 script_xref(name:"MSFT", value:"MS06-028");

 script_name(english:"MS06-028: Vulnerabilities in Microsoft PowerPoint Could Allow Remote Code Execution (916768)");
 script_summary(english:"Determines the version of PowerPoint.exe");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
PowerPoint.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft PowerPoint that is
subject to a fla that could allow arbitrary code to be run.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it.  Then a bug in the font parsing
handler would result in code execution.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-028");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for PowerPoint 2000, XP and
2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/06/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS06-028';
kbs = make_list("916518", "916519", "916520", "916768");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);
port = get_kb_item("SMB/transport");


kb = '916768';

#
# PowerPoint
#
vuln = 0;
list = get_kb_list_or_exit("SMB/Office/PowerPoint/*/ProductPath");
foreach item (keys(list))
{
  v = list - 'SMB/Office/PowerPoint/' - '/ProductPath';
  if(ereg(pattern:"^9\..*", string:v))
  {
    # PowerPoint 2000 - fixed in 9.00.00.8942
    office_sp = get_kb_item("SMB/Office/2000/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      kb = '916520';
      sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
      if(sub != v && int(sub) < 8942 ) {
        vuln++;
        hotfix_add_report(bulletin:bulletin, kb:kb);
      }
    }
  }
  else if(ereg(pattern:"^10\..*", string:v))
  {
    # PowerPoint XP - fixed in 10.0.6800.0
    office_sp = get_kb_item("SMB/Office/XP/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      kb = '916519';
      middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
      if(middle != v && int(middle) < 6800) {
        vuln++;
        hotfix_add_report(bulletin:bulletin, kb:kb);
      }
    }
  }
  else if(ereg(pattern:"^11\..*", string:v))
  {
    # PowerPoint 2003 - fixed in 11.8024.0
    office_sp = get_kb_item("SMB/Office/2003/SP");
    if (!isnull(office_sp) && (office_sp == 1 || office_sp == 2))
    {
      kb = '916518';
      middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
      if(middle != v && int(middle) < 8024) {
        vuln++;
        hotfix_add_report(bulletin:bulletin, kb:kb);
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
