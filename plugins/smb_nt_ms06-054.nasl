#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22334);
 script_version("$Revision: 1.27 $");
 script_cvs_date("$Date: 2016/06/30 19:55:38 $");

 script_cve_id("CVE-2006-0001");
 script_bugtraq_id(19951);
 script_osvdb_id(28730);
 script_xref(name:"MSFT", value:"MS06-054");

 script_name(english:"MS06-054: Vulnerability in Microsoft Publisher Could Allow Remote Code Execution (910729)");
 script_summary(english:"Determines the version of MSPUB.exe");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Publisher.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Publisher that could
allow arbitrary code to be run.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it.  Then a bug in the font parsing
handler would result in code execution.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-054");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Publisher 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/09/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/12");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:publisher");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_nt_ms02-031.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS06-054';
kbs = make_list("894540", "894541", "894542", "910729");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);
port = get_kb_item("SMB/transport");


kb = '910729';

#
# PowerPoint
#
vulns = 0;
list = get_kb_list_or_exit("SMB/Office/Publisher/*/ProductPath");
foreach item (keys(list))
{
  v = item - 'SMB/Office/Publisher/' - '/ProductPath';
  if(ereg(pattern:"^9\..*", string:v))
  {
    # Publisher 2000 - fixed in 9.00.00.8930
    kb = '894540';
    sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
    if(sub != v && int(sub) < 8930 ) {
      vuln++;
      hotfix_add_report(bulletin:bulletin, kb:kb);
    }
  }
  else if(ereg(pattern:"^10\..*", string:v))
  {
    # Publisher XP - fixed in 10.0.6815.0
    kb = '894541';
    middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
    if(middle != v && int(middle) < 6815) {
      vuln++;
      hotfix_add_report(bulletin:bulletin, kb:kb);
    }
  }
  else if(ereg(pattern:"^11\..*", string:v))
  {
    # Publisher 2003 - fixed in 11.0.8103.0
    kb = '894542';
    middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
    if(middle != v && int(middle) < 8103) {
      vuln++;
      hotfix_add_report(bulletin:bulletin, kb:kb);
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
