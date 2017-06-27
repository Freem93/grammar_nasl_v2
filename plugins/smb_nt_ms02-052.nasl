#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11177);
 script_version("$Revision: 1.44 $");
 script_cvs_date("$Date: 2017/05/26 15:15:35 $");

 script_cve_id(
   "CVE-2002-1257",
   "CVE-2002-1258",
   "CVE-2002-1260",
   "CVE-2002-1292",
   "CVE-2002-1295",
   "CVE-2002-1325"
 );
 script_bugtraq_id(6371,6372,6379,6380);
 script_osvdb_id(11914, 13412, 13417, 13418, 7885, 7886);
 script_xref(name:"CERT", value:"897529");
 script_xref(name:"CERT", value:"422807");
 script_xref(name:"MSFT", value:"MS02-052");
 script_xref(name:"MSFT", value:"MS02-069");
 script_xref(name:"MSKB", value:"329077");

 script_name(english:"MS02-052: Flaw in Microsoft VM Could Allow Code Execution (810030)");
 script_summary(english:"Checks for MS Hotfix Q329077, Flaw in Microsoft VM JDBC");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the VM.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a Microsoft VM machine that has a bug
in its bytecode verifier that could allow a remote attacker to execute
arbitrary code on this host, with the privileges of the SYSTEM.

To exploit this vulnerability, an attacker would need to send a malformed
applet to a user on this host, and have him execute it. The malicious
applet would then be able to execute code outside the sandbox of the VM.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms02-052");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows NT, 2000 and XP.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/11/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/09/18");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/11/28");

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

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS02-052';
kb = '329077';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

if ( hotfix_check_sp(nt:7, xp:2, win2k:4) <= 0 ) exit(0);

version = get_kb_item ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Active Setup/Installed Components/{08B0E5C0-4FCB-11CF-AAA5-00401C608500}/Version");
if (!version) exit(0);


v = split(version, sep:",", keep:FALSE);
if ( int(v[0]) < 5 ||
     ( int(v[0]) == 5 && int(v[1]) == 0 && int(v[2]) < 3807) )
{
 if ( hotfix_missing(name:"810030") > 0 )
 {
 set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_hole();
 }
}


