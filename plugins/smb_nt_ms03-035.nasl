#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11831);
 script_version("$Revision: 1.40 $");
 script_cvs_date("$Date: 2017/05/25 13:29:27 $");

 script_cve_id("CVE-2003-0664");
 script_bugtraq_id(8533);
 script_osvdb_id(2506, 10935);
 script_xref(name:"MSFT", value:"MS03-035");
 script_xref(name:"MSKB", value:"827653");

 script_name(english:"MS03-035: Word Macros may run automatically (827653)");
 script_summary(english:"Determines the version of WinWord.exe");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through VBA.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Word that contains a
flaw in its handling of macro command execution.  An attacker could use
this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue Word file to a user
of this computer and have him open it.  Then the macros contained in the
Word file would bypass the security model of Word and be executed.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms03-035");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/09/03");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/09/03");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/09/04");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:works");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_nt_ms02-031.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports("SMB/Office/Word/Version", "Host/patch_management_checks");

 exit(0);
}

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS03-035';
kb = '827653';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

port = get_kb_item("SMB/transport");
list = get_kb_list_or_exit("SMB/Office/Word/*/ProductPath");

vuln = 0;
foreach item (keys(list))
{
  v = item - 'SMB/Office/Word/' - '/ProductPath';
  if(ereg(pattern:"^10\..*", string:v))
  {
    # Word 2002 - updated in 10.0.5522.0
    middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
    if(middle != v && int(middle) < 5522) {
      vuln++;
      hotfix_add_report(bulletin:bulletin, kb:kb);
    }
  }
  else if(ereg(pattern:"^9\..*", string:v))
  {
    # Word 2000 - fixed in 9.00.00.7924
    sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
    if(sub != v && int(sub) < 7924) {
      vuln++;
      hotfix_add_report(bulletin:bulletin, kb:kb);
    }
  }
  else if(ereg(pattern:"^8\..*", string:v))
  {
    # Word 97 - fixed in 8.0.0.8125
    sub =  ereg_replace(pattern:"^8\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
    if(sub != v && int(sub) < 8125) {
      vuln++;
      hotfix_add_report(bulletin:bulletin, kb:kb);
    }
  }
}
if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
audit(AUDIT_HOST_NOT, 'affected');
