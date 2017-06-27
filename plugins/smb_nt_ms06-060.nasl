#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22533);
 script_version("$Revision: 1.36 $");
 script_cvs_date("$Date: 2016/07/11 14:12:52 $");

 script_cve_id(
  "CVE-2006-3647",
  "CVE-2006-3651",
  "CVE-2006-4534",
  "CVE-2006-4693"
 );
 script_bugtraq_id(19835, 20341, 20358);
 script_osvdb_id(28539, 29440, 29441, 29442);
 script_xref(name:"CERT", value:"806548");
 script_xref(name:"MSFT", value:"MS06-060");

 script_name(english:"MS06-060: Vulnerabilities in Microsoft Word Could Allow Remote Code Execution (924554)");
 script_summary(english:"Determines the version of WinWord.exe");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Word.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Word that may allow
arbitrary code to be run.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it.  Then a bug in the font parsing
handler would result in code execution.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-060");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Word 2000, XP and 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_cwe_id(189);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/03");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/10/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:works");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("office_installed.nasl", "smb_nt_ms02-031.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS06-060';
kbs = make_list("920817", "920910", "923094", "924554");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

port = get_kb_item("SMB/transport");
kb = '924554';

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
    # Word 2000 - fixed in 9.00.00.8951
    office_sp = get_kb_item("SMB/Office/2000/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      kb = '920910';
      sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
      if(sub != v && int(sub) < 8951 ) {
        vuln++;
        hotfix_add_report(bulletin:bulletin, kb:kb);
      }
    }
  }
  else if(ereg(pattern:"^10\..*", string:v))
  {
    # Word XP - fixed in 10.0.6818.0
    office_sp = get_kb_item("SMB/Office/XP/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      kb = '920817';
      middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
      if(middle != v && int(middle) < 6818) {
        vuln++;
        hotfix_add_report(bulletin:bulletin, kb:kb);
      }
    }
  }
  else if(ereg(pattern:"^11\..*", string:v))
  {
    # Word 2003 - fixed in 11.08104.0
    office_sp = get_kb_item("SMB/Office/2003/SP");
    if (!isnull(office_sp) && (office_sp == 1 || office_sp == 2))
    {
      kb = '923094';
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
  hotfix_security_warning();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
