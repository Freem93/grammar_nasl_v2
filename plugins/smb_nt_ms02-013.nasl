#
# (C) Tenable Network Security, Inc.
#

# Ref: https://technet.microsoft.com/library/security/ms02-013
#
# Supercedes : MS99-031, MS99-045, MS00-011, MS00-059, MS00-075, MS00-081
#


include("compat.inc");

if (description)
{
 script_id(11326);
 script_version("$Revision: 1.47 $");
 script_cvs_date("$Date: 2017/05/26 15:15:34 $");

 script_cve_id("CVE-2002-0058", "CVE-2002-0076");
 script_bugtraq_id(4228, 4313);
 script_osvdb_id(5376, 14270);
 script_xref(name:"MSFT", value:"MS02-013");
 script_xref(name:"MSKB", value:"300845");

 script_name(english:"MS02-013: Cumulative VM Update (300845)");
 script_summary(english:"Determines the version of JView.exe");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host through the VM.");
 script_set_attribute(attribute:"description", value:
"The Microsoft VM is a virtual machine for the Win32 operating
environment.

There are numerous security flaws in the remote Microsoft VM that could
allow an attacker to execute arbitrary code on this host.

To exploit these flaws, an attacker would need to set up a malicious web
site with a rogue Java applet and lure the user of this host to visit
it.  The Java applet could then execute arbitrary commands on this
host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms02-013");
 script_set_attribute(attribute:"solution", value:
"Microsoft VM is no longer supported, and previous updates are no no
longer available.  Upgrade to an actively supported product.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/03/04");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/03/04");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/06");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_nt_ms03-011.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS02-013';
kb = '300845';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

if (hotfix_check_sp(nt:7, win2k:4, xp:1) <= 0) exit(0, 'The host is not affected based on its version / service pack.');

if (  get_kb_item("KB816093") ) exit(0, "KB816093 is installed.");
if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");


if (hotfix_is_vulnerable(file:"Jview.exe",version:"5.0.3.3805",dir:"\system32", bulletin:bulletin, kb:kb))
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected");
}


