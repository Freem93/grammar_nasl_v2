#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11992);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2015/04/23 21:04:49 $");

 script_cve_id("CVE-2003-0819");
 script_bugtraq_id(9408);
 script_osvdb_id(11712);
 script_xref(name:"CERT", value:"749342");
 script_xref(name:"MSFT", value:"MS04-001");

 script_name(english:"MS04-001: Vulnerability in Microsoft ISA Server 2000 H.323 Filter(816458)");
 script_summary(english:"Checks for hotfix Q816458");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"A buffer overflow vulnerability in the H.323 filter of the Microsoft
ISA Server 2000 allows an attacker to execute arbitrary code on the
remote host.  An attacker can exploit this vulnerability by sending a
specially crafted packet to the remote ISA Server.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms04-001");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for ISA Server Gold and SP1.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/01/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/01/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/01/14");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS04-001';
kb = '948881';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

port = get_kb_item("SMB/transport");
if(!port)port = 139;

access = get_kb_item("SMB/registry_full_access");
if(!access)exit(0);

path = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
if (!path) exit(0, "ISA Server does not appear to be installed.");


if (is_accessible_share ())
{
 if ( hotfix_check_fversion(path:path, file:"H323asn1.dll", version:"3.0.1200.291", bulletin:bulletin, kb:kb) == HCF_OLDER )
 {
  set_kb_item(name:"SMB/Missing/MS04-001", value:TRUE);
  hotfix_security_hole();
 }
 hotfix_check_fversion_end();
}
else
{
 #superseded by SP2
 fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/365");
 if(fix) exit(0);

 fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/291");
 if(!fix)
 {
  set_kb_item(name:"SMB/Missing/MS04-001", value:TRUE);
  hotfix_add_report(bulletin:bulletin, kb:kb);
  hotfix_security_hole();
 }
}
