#
# (C) Tenable Network Security, Inc.
#

# MS03-033 supercedes MS02-040
#
# Note: The fix for this issue will be included in MDAC 2.5 Service Pack 5 and in MDAC 2.7 Service Pack 2.
# The script should be update when the service pack is released.
#
# MS03-033 Prerequisites:
# You must be running one of the following versions of MDAC:
# MDAC 2.5 Service Pack 2
# MDAC 2.5 Service Pack 3
# MDAC 2.6 Service Pack 2
# MDAC 2.7 RTM
# MDAC 2.7 Service Pack 1
# Other versions of MDAC are not affected by this vulnerability.
#
# MS02-040 Fixed in :
#	- MDAC 2.5 SP3
#	- MDAC 2.6 SP3
#	- MDAC 2.7 SP1
#

include("compat.inc");

if (description)
{
 script_id(11301);
 script_version("$Revision: 1.51 $");
 script_cvs_date("$Date: 2017/05/26 15:15:35 $");

 script_cve_id("CVE-2002-0695", "CVE-2003-0353");
 script_bugtraq_id(5372, 8455);
 script_osvdb_id(5135, 10129);
 script_xref(name:"MSFT", value:"MS02-040");
 script_xref(name:"MSFT", value:"MS03-033");
 script_xref(name:"MSKB", value:"326573");

 script_name(english:"MS02-040 / MS03-033: Unchecked buffer in MDAC Function (326573 / 823718)");
 script_summary(english:"Checks the version of MDAC");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through MDAC
server.");
 script_set_attribute(attribute:"description", value:
"The remote Microsoft Data Access Component (MDAC) server is vulnerable
to a flaw that could allow an attacker to execute arbitrary code on this
host, provided he can load and execute a database query on this
server.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms02-040");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms03-033");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for MDAC 2.6, 2.7 and 2.8.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/08/20");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/07/31");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/01");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:data_access_components");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
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

bulletin = 'MS02-040';
kb = '326573';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

if (!get_kb_item("SMB/WindowsVersion")) exit(1, "SMB/WindowsVersion KB item is missing.");
if ( hotfix_check_sp(nt:7, xp:2, win2k:5) <= 0 ) exit(0, "Host is not affected based on its version / service pack.");

if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");


if (
  hotfix_is_vulnerable(file:"odbcbcp.dll", min_version:"3.0.0.0", version:"3.70.11.40", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(file:"odbcbcp.dll", min_version:"2000.80.0.0", version:"2000.80.746.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(file:"odbcbcp.dll", min_version:"2000.81.0.0", version:"2000.81.9001.40", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(file:"odbcbcp.dll", min_version:"2000.81.9030.0", version:"2000.81.9041.40", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/MS02-040", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected");
}


