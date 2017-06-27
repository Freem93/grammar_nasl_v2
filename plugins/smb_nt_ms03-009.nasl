#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11433);
 script_version("$Revision: 1.37 $");
 script_cvs_date("$Date: 2017/05/25 13:29:26 $");

 script_cve_id("CVE-2003-0011");
 script_bugtraq_id(7145);
 script_osvdb_id(14396);
 script_xref(name:"MSFT", value:"MS03-009");
 script_xref(name:"MSKB", value:"331065");

 script_name(english:"MS03-009: Microsoft ISA Server DNS - Denial Of Service (331065)");
 script_summary(english:"Checks for ISA Server DNS HotFix SP1-256");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to launch a denial of service attack against the
remote DNS application filter.");
 script_set_attribute(attribute:"description", value:
"A vulnerability in Microsoft ISA Server 2000 allows an attacker to
cause a denial of service in DNS services by sending a specially
crafted DNS request packet.

Note that, to be vulnerable, the ISA Server must be manually
configured to publish an internal DNS server, which it does not do by
default.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms03-009");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for ISA Server 2000.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/03/19");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/03/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/21");

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

bulletin = 'MS03-009';
kb = "331065";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_NOTE);

get_kb_item_or_exit('SMB/WindowsVersion');

port = get_kb_item("SMB/transport");
if (!port) port = 139;

access = get_kb_item_or_exit("SMB/registry_full_access");

path = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
if (!path) exit(0, "ISA Server does not appear to be installed.");


if (is_accessible_share())
{
  if (hotfix_check_fversion(path:path, file:"Issfltr.dll", version:"3.0.1200.256", bulletin:bulletin, kb:kb) == HCF_OLDER)
  {
    hotfix_security_note();

    set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
    hotfix_check_fversion_end();
    exit(0);
  }
  hotfix_check_fversion_end();
}
else
{
  # Superseded by SP2
  fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/365");
  if (fix) exit(0, "The host is not affected as SP2 is installed.");

  fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/256");
  if (!fix)
  {
    if (
      defined_func("report_xml_tag") &&
      !isnull(bulletin) &&
      !isnull(kb)
    ) report_xml_tag(tag:bulletin, value:kb);

    hotfix_security_note();
    set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
    exit(0);
  }
}

exit(0, "The host is not affected.");
