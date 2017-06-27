#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22532);
 script_version("$Revision: 1.33 $");
 script_cvs_date("$Date: 2016/06/30 19:55:38 $");

 script_cve_id(
  "CVE-2006-2387",
  "CVE-2006-3431",
  "CVE-2006-3867",
  "CVE-2006-3875"
 );
 script_bugtraq_id(18872, 20344, 20345, 20391);
 script_osvdb_id(27053, 29443, 29444, 29445);
 script_xref(name:"MSFT", value:"MS06-059");

 script_name(english:"MS06-059: Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (924164)");
 script_summary(english:"Determines the version of Excel.exe");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Excel.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Excel that may allow
arbitrary code to be run.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it with Microsoft Excel.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-059");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Excel 2000, XP and 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/03");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/10/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:xml_core_services");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, "Host/patch_management_checks");

 exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS06-059';
kbs = make_list("923088", "923089", "923090", "924164");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

port = get_kb_item("SMB/transport");
kb = '924164';

#
# Excel
#
vuln = 0;
list = get_kb_list_or_exit("SMB/Office/Excel/*/ProductPath");
foreach item (keys(list))
{
  v = item - 'SMB/Office/Excel/' - '/ProductPath';
  if(ereg(pattern:"^9\..*", string:v))
  {
    # Excel 2000 - fixed in 9.00.00.8950
    office_sp = get_kb_item("SMB/Office/2000/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      kb = '923090';
      sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
      if(sub != v && int(sub) < 8950 ) {
        vuln++;
       hotfix_add_report(bulletin:bulletin, kb:kb);
      }
    }
  }
  else if(ereg(pattern:"^10\..*", string:v))
  {
    # Excel XP - fixed in 10.0.6816.0
    office_sp = get_kb_item("SMB/Office/XP/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      kb = '923089';
      middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
      if(middle != v && int(middle) < 6816) {
        vuln++;
        hotfix_add_report(bulletin:bulletin, kb:kb);
      }
    }
  }
  else if(ereg(pattern:"^11\..*", string:v))
  {
    # Excel 2003 - fixed in 11.0.8104.0
    office_sp = get_kb_item("SMB/Office/2003/SP");
    if (!isnull(office_sp) && (office_sp == 1 || office_sp == 2))
    {
      kb = '923088';
      middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
      if(middle != v && int(middle) < 8104) {
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
