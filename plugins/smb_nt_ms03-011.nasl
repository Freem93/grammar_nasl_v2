#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11528);
 script_version("$Revision: 1.35 $");
 script_cvs_date("$Date: 2017/05/25 13:29:26 $");

 script_cve_id("CVE-2003-0111");
 script_bugtraq_id(6221);
 script_osvdb_id(2969);
 script_xref(name:"MSFT", value:"MS03-011");
 script_xref(name:"CERT", value:"447569");
 script_xref(name:"MSKB", value:"816093");

 script_name(english:"MS03-011: Flaw in Microsoft VM (816093)");
 script_summary(english:"Checks for the version of the remote VM");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the VM.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a Microsoft VM machine that has a bug in
its bytecode verifier that could allow a remote attacker to execute
arbitrary code on this host with the privileges of the user running
the VM.

To exploit this vulnerability, an attacker would need to send a
malformed applet to a user on this host and have him execute it.  The
malicious applet would then be able to execute code outside the
sandbox of the VM.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms03-011");
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/gp/lifean12");
 script_set_attribute(attribute:"solution", value:
"Microsoft VM is no longer supported, and previous updates are no
longer available.  Upgrade to an actively supported product.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/11/21");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/04/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/04/10");

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

bulletin = 'MS03-011';
kb = "816093";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

if (hotfix_check_sp(nt:7, win2k:4, xp:2) <= 0) exit(0, 'The host is not affected based on its version / service pack.');

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");


if (hotfix_is_vulnerable(file:"Jview.exe",version:"5.0.3810.0",dir:"\system32", bulletin:bulletin, kb:kb))
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected.");
}
