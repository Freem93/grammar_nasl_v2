#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11534);
 script_version("$Revision: 1.37 $");
 script_cvs_date("$Date: 2017/05/25 13:29:26 $");

 script_cve_id("CVE-2003-0110");
 script_bugtraq_id(7314);
 script_osvdb_id(6967);
 script_xref(name:"MSFT", value:"MS03-012");
 script_xref(name:"MSKB", value:"331066");

 script_name(english:"MS03-012: Microsoft ISA Server Winsock Proxy DoS (331066)");
 script_summary(english:"Checks for ISA Server HotFix SP1-257");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to launch a denial of service attack against the
remote proxy server.");
 script_set_attribute(attribute:"description", value:
"A vulnerability in Microsoft Proxy Server 2.0 and ISA Server 2000
allows an attacker to cause a denial of service of the remote Winsock
proxy service by sending a specially crafted packet that would cause
100% CPU utilization on the remote host and make it unresponsive.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms03-012");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for ISA Server 2000.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/04/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/04/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/04/13");

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

bulletin = 'MS03-012';
kb = "331066";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

port = get_kb_item("SMB/transport");
if (!port)port = 139;

access = get_kb_item_or_exit("SMB/registry_full_access");

path = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
if (!path) exit(0, "ISA Server does not appear to be installed.");


if (is_accessible_share())
{
  if (hotfix_check_fversion(path:path, file:"W3proxy.exe", version:"3.0.1200.257", bulletin:bulletin, kb:kb) == HCF_OLDER)
  {
    hotfix_security_hole();

    set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
    hotfix_check_fversion_end();
    exit(0);
  }
  hotfix_check_fversion_end();
}
else
{
  # Superseded by MS04-039.
  fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/408");
  if (fix) exit(0, "The host is not affected as the update for MS04-039 has been applied.");

  # Superseded by SP2
  fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/365");
  if (fix) exit(0, "The host is not affected as SP2 is installed.");

  fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/257");
  if (!fix)
  {
    if (
      defined_func("report_xml_tag") &&
      !isnull(bulletin) &&
      !isnull(kb)
    ) report_xml_tag(tag:bulletin, value:kb);

    hotfix_security_hole();
    set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
    exit(0);
  }
}

exit(0, "The host is not affected.");
