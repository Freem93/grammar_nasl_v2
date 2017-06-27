#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10563);
  script_version("$Revision: 1.44 $");
  script_cvs_date("$Date: 2017/05/26 15:15:34 $");

  script_cve_id("CVE-2000-1039");
  script_bugtraq_id(2022);
  script_osvdb_id(462);
  script_xref(name:"MSFT", value:"MS00-091");
  script_xref(name:"MSKB", value:"275567");

  script_name(english:"MS00-091: Incomplete TCP/IP Packet Vulnerability (199346)");
  script_summary(english:"Determines whether the hotfix Q274372 is installed");

  script_set_attribute(attribute:"synopsis", value:"The remote host is vulnerable to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"The hotfix for the 'incomplete TCP/IP packet' problem has not been
applied.

This vulnerability allows a user to prevent this host from communicating
with the network.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms00-091");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patches from MS00-091 or apply the latest Windows
service pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2000/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/12/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2000-2017 Tenable Network Security, Inc.");
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

bulletin = 'MS00-091';
kb = "275567";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp(nt:7) <= 0) exit(0, "The host is not affected based on its version / service pack.");


if (
  hotfix_missing(name:"Q299444") > 0 &&
  hotfix_missing(name:"Q275567") > 0
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


