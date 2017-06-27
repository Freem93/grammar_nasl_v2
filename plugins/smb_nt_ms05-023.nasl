#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18026);
 script_version("$Revision: 1.35 $");
 script_cvs_date("$Date: 2017/03/30 13:31:43 $");

 script_cve_id("CVE-2004-0963", "CVE-2005-0558");
 script_bugtraq_id(13122, 13119);
 script_osvdb_id(10549, 15470);
 script_xref(name:"MSFT", value:"MS05-023");

 script_name(english:"MS05-023: Vulnerability in Word May Lead to Code Execution (890169)");
 script_summary(english:"Determines the version of WinWord.exe");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Word.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Word that could allow
arbitrary code to be run.

To succeed, the attacker would have to send a rogue Word file to a user
of the remote computer and have it open it.  Then the macros contained
in the Word file would bypass the security model of Word, and would be
executed.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms05-023");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Word 2000, 2002 and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/04/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/12");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_nt_ms02-031.nasl", "smb_nt_ms05-035.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS05-023';
kbs = make_list("887978", "891067");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);
port = get_kb_item("SMB/transport");

if (get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Updates/KB903672")) exit(0);

vuln = 0;
list = get_kb_list_or_exit("SMB/Office/Word/*/ProductPath");
foreach item (keys(list))
{
  v = item - 'SMB/Office/Word/' - '/ProductPath';
  if(ereg(pattern:"^11\..*", string:v))
  {
    # Word 2003 - updated in 11.0.6425.0
    middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
    if(middle != v && int(middle) < 6425) {
      vuln++;
      hotfix_add_report(bulletin:bulletin, kb:'891067');
    }
  }
  else if(ereg(pattern:"^10\..*", string:v))
  {
    # Word 2002 - updated in 10.0.6754.0
    middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
    if(middle != v && int(middle) < 6754 ) {
      vuln++;
      hotfix_add_report(bulletin:bulletin, kb:'887978');
    }
  }
  else if(ereg(pattern:"^9\..*", string:v))
  {
    # Word 2000 - fixed in 9.00.00.8929
    sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
    if(sub != v && int(sub) < 8929) {
      vuln++;
      hotfix_add_report(bulletin:bulletin, kb:'887978');
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
