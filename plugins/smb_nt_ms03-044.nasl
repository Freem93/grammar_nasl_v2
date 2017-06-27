#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11928);
 script_version("$Revision: 1.37 $");
 script_cvs_date("$Date: 2017/05/25 13:29:27 $");

 script_cve_id("CVE-2003-0711");
 script_bugtraq_id(8828);
 script_osvdb_id(11462);
 script_xref(name:"MSFT", value:"MS03-044");
 script_xref(name:"CERT", value:"467036");
 script_xref(name:"MSKB", value:"825119");

 script_name(english:"MS03-044: Buffer Overrun in Windows Help (825119)");
 script_summary(english:"Checks for hotfix 825119");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the Help
service.");
 script_set_attribute(attribute:"description", value:
"A security vulnerability exists in the Windows Help Service that could
allow arbitrary code execution on an affected system.  An attacker who
successfully exploited this vulnerability could run code with Local
System privileges on this host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms03-044");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/10/15");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/10/15");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/11/17");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
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

bulletin = 'MS03-044';
kb = '825119';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


if (!get_kb_item("SMB/WindowsVersion")) exit(1, "SMB/WindowsVersion KB item is missing.");
if (hotfix_check_sp(nt:7, win2k:6, xp:2, win2003:1) <= 0) exit(0, "Host is not affected based on its version / service pack.");

if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");


if (hotfix_is_vulnerable(file:"itircl.dll", version:"5.2.3790.80", dir:"\system32", bulletin:bulletin, kb:kb))
{
  set_kb_item(name:"SMB/Missing/MS03-044", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected");
}
