#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11307);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2017/05/26 15:15:34 $");

 script_cve_id("CVE-2002-0070");
 script_bugtraq_id(4248);
 script_osvdb_id(2051);
 script_xref(name:"CERT", value:"152867");
 script_xref(name:"MSFT", value:"MS02-014");
 script_xref(name:"MSKB", value:"313829");

 script_name(english:"MS02-014: Unchecked buffer in Windows Shell (313829)");
 script_summary(english:"Checks for MS Hotfix Q216840");

 script_set_attribute(attribute:"synopsis", value:"A local user can elevate privileges.");
 script_set_attribute(attribute:"description", value:
"The Windows shell of the remote host has an unchecked buffer that can
be exploited by a local attacker to run arbitrary code on this host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms02-014");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows NT and 2000.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/03/07");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/03/07");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/02");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, "Host/patch_management_checks");

 exit(0);
}

#

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS02-014';
kb = '313829';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

if ( hotfix_check_sp(nt:7, win2k:3) <= 0 ) exit(0);
if ( hotfix_check_sp(win2k:3) > 0 )
{
 if ( hotfix_missing(name:"839645") == 0 ) exit(0);
}


if ( hotfix_missing(name:kb) > 0 && hotfix_missing(name:"841356") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_hole();
 }


