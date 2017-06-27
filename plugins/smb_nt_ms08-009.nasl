#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(31043);
 script_version("$Revision: 1.31 $");
 script_cvs_date("$Date: 2016/06/30 19:55:38 $");

 script_cve_id("CVE-2008-0109");
 script_bugtraq_id(27656);
 script_osvdb_id(41464);
 script_xref(name:"MSFT", value:"MS08-009");

 script_name(english:"MS08-009: Vulnerabilities in Microsoft Word Could Allow Remote Code Execution (947077)");
 script_summary(english:"Determines the version of WinWord.exe");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Word.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Word that is subject
to a flaw that could allow arbitrary code to be run.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it.  Then a bug in the font parsing
handler would result in code execution.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS08-009");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Word 2000, XP and 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_cwe_id(399);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/02/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/02/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/12");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, "Host/patch_management_checks");

 exit(0);
}

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS08-009';
kbs = make_list("943957", "943983", "943990");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

port = get_kb_item("SMB/transport");


kb = '';

#
# Word
#
vuln = 0;
list = get_kb_list_or_exit("SMB/Office/Word/*/ProductPath");
foreach item (keys(list))
{
  v = item - 'SMB/Office/Word/' - '/ProductPath';
  if(ereg(pattern:"^9\..*", string:v))
  {
    # Word 2000 - fixed in 9.0.0.8966
    office_sp = get_kb_item("SMB/Office/2000/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
      if(sub != v && int(sub) < 8966 ) {
        vuln++;
        kb = '943990';
        hotfix_add_report(bulletin:bulletin, kb:kb);
      }
    }
  }
  else if(ereg(pattern:"^10\..*", string:v))
  {
    # Word XP - fixed in 10.0.6838.0
    office_sp = get_kb_item("SMB/Office/XP/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
      if(middle != v && int(middle) < 6838) {
        vuln++;
        kb = '943957';
        hotfix_add_report(bulletin:bulletin, kb:kb);
      }
    }
  }
  else if(ereg(pattern:"^11\..*", string:v))
  {
    # Word 2003 - fixed in 11.0.8169.0 (SP3)
    office_sp = get_kb_item("SMB/Office/2003/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
      if(middle != v && int(middle) < 8169) {
        vuln++;
        kb = '943983';
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
