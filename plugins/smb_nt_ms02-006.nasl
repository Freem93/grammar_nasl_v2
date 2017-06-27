#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10865);
 script_version("$Revision: 1.46 $");
 script_cvs_date("$Date: 2017/05/26 15:15:34 $");

 # "CVE-2002-0012" and "CVE-2002-0013" too?
 script_cve_id("CVE-2002-0053");
 script_bugtraq_id(4089);
 script_osvdb_id(4850);
 script_xref(name:"CERT", value:"107186");
 script_xref(name:"CERT", value:"854306");
 script_xref(name:"MSFT", value:"MS02-006");
 script_xref(name:"MSKB", value:"314147");

 script_name(english:"MS02-006: Malformed SNMP Management Request Remote Overflow (314147)");
 script_summary(english:"Determines the presence of hotfix Q314147");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"A buffer overrun is present in the SNMP service on the remote host.  By
sending a malformed management request, an attacker could cause a denial
of service and possibly cause code to run on the system in the
LocalSystem context.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms02-006");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows NT, 2000 and XP.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/02/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/02/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/02/22");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2017 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS02-006';
kb = '314147';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


if ( hotfix_check_sp(nt:7, xp:1, win2k:3) <= 0 ) exit(0);


if ( hotfix_missing(name:kb) > 0  )
 {
 set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_hole();
 }


