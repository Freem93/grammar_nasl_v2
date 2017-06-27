#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10734);
 script_version("$Revision: 1.50 $");
 script_cvs_date("$Date: 2017/05/26 15:15:34 $");

 script_cve_id("CVE-2001-0659");
 script_bugtraq_id(3215);
 script_osvdb_id(608);
 script_xref(name:"MSFT", value:"MS01-046");
 script_xref(name:"MSKB", value:"252795");

 script_name(english:"MS01-046: IrDA Driver Malformed Packet Remote DoS (252795)");
 script_summary(english:"Determines whether the hotfix Q252795 is installed");

 script_set_attribute(attribute:"synopsis", value:"It is possible to remotely shutdown the server.");
 script_set_attribute(attribute:"description", value:
"The hotfix for the 'IrDA access violation patch' problem has not been
applied.

This vulnerability can allow an attacker who is physically near the
W2K host to shut it down using a remote control.");
 # http://web.archive.org/web/20050316084636/support.microsoft.com/kb/311401
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43a53d15");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms01-046");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Windows 2000.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/08/21");
 script_set_attribute(attribute:"patch_publication_date", value:"2001/08/21");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/08/24");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2017 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, "Host/patch_management_checks");

 exit(0);
}

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS01-046';
kb = "252795";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);


if (hotfix_check_sp(win2k:3) <= 0) exit(0, "The host is not affected based on its version / service pack.");


if (
  hotfix_missing(name:"SP2SRP1") > 0 &&
  hotfix_missing(name:"Q252795") > 0
)
{
  if (
    defined_func("report_xml_tag") &&
    !isnull(bulletin) &&
    !isnull(kb)
  ) report_xml_tag(tag:bulletin, value:kb);

  hotfix_security_warning();
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  exit(0);
}
else exit(0, "The host is not affected.");


