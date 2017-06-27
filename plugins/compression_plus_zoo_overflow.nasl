#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(22308);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/17 21:38:53 $");

  script_cve_id("CVE-2006-4554");
  script_bugtraq_id(19796);
  script_osvdb_id(28371);

  script_name(english:"Compression Plus CP5DLL32.DLL ZOO Archive Header Processing Overflow RCE");
  script_summary(english:"Checks version of Compression Plus cp5dll32.dll.");

  script_set_attribute(attribute:"synopsis", value:
"A library file installed on the remote Windows host is affected by a
remote code execution vulnerability." );
  script_set_attribute(attribute:"description", value:
"The version of the Compression Plus toolkit installed on the remote
Windows host contains a DLL file that is affected by a stack-based
overflow condition when processing specially crafted ZOO files. A
remote attacker can exploit this issue, via an inconsistent size
parameter in a ZOO file header, to execute arbitrary code." );
  script_set_attribute(attribute:"see_also", value:"http://www.mnin.org/advisories/2006_cp5_tweed.pdf");
  # https://web.archive.org/web/20060306012233/http://becubed.com/downloads/compfix.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5977525c");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor for a fix or upgrade file Cp5dll32.dll to version
5.0.1.28 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  
  script_set_attribute(attribute:"vuln_publication_date", value: "2006/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value: "2006/09/06");
  
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

sys_root = hotfix_get_systemroot();
if (!sys_root || !is_accessible_share()) exit(0);

if (
  hotfix_check_fversion(
    file    : "Cp5dll32.dll",
    path    : sys_root + "\system32",
    version : "5.0.1.28"
  ) == HCF_OLDER
)
{
  security_warning(get_kb_item("SMB/transport"));
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
