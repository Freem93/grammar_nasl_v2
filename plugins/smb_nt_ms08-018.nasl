#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(31791);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2016/06/30 19:55:38 $");

 script_cve_id("CVE-2008-1088");
 script_bugtraq_id(28607);
 script_osvdb_id(44212);
 script_xref(name:"CERT", value:"155563");
 script_xref(name:"MSFT", value:"MS08-018");

 script_name(english:"MS08-018: Vulnerability in Microsoft Project Could Allow Remote Code Execution (950183)");
 script_summary(english:"Determines the presence of update 950183");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Project.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Project that has a
vulnerability in the way it validates memory that could be used by an
attacker to execute arbitrary code on the remote host.

To exploit this vulnerability, an attacker would need to spend a
specially crafted Project document to a user on the remote host and lure
him into opening it.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms08-018");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Project 2000, 2002
and 2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(399);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/04/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/04/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "smb_nt_ms02-031.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, "Host/patch_management_checks");

 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS08-018';
kbs = make_list("950183");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

list = get_kb_list_or_exit("SMB/Office/Project/*/ProductPath");

vers9  = make_list(9, 0,2008, 228);
vers10 = make_list(10,0,2108,1228);
vers11 = make_list(11,3,2007,1529); # SP3

vuln = 0;
foreach item (keys(list))
{
  ref = NULL;
  path = list[item];
  item = item - 'SMB/Office/Project/' - '/ProductPath';
  vers = split(item, sep:'.', keep:FALSE);
  for (i=0; i<max_index(vers); i++) vers[i] = int(vers[i]);

  if ( vers[0] == 9 ) ref = vers9;
  else if ( vers[0] == 10 ) ref = vers10;
  else if ( vers[0] == 11 ) ref = vers11;

  if (ref)
  {
    for ( i = 0 ; i < max_index(vers) ; i ++ )
    {
      if ( vers[i] < ref[i] )
	    {
        vuln++;
        report =
          '\n  Path              : ' + path +
          '\n  Installed version : ' + item +
          '\n  Fixed version     : ' + join(ref, sep:'.') + '\n';

        kb       = '950183';
        hotfix_add_report(report, bulletin:bulletin, kb:kb);
        break;
      }
      else if ( vers[i] > ref[i] ) break;
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
