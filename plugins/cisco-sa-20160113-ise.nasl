#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97469);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/03/06 14:38:26 $");
  
  script_cve_id("CVE-2015-6323");
  script_bugtraq_id(80497);
  script_osvdb_id(132862);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw34253");
  script_xref(name:"IAVA", value:"2016-A-0029");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160113-ise");

  script_name(english:"Cisco Identify Services Engine (ISE) Admin Portal Unauthorized Access");
  script_summary(english:"Checks the Cisco Identify Services Engine version.");

  script_set_attribute(attribute:"synopsis", value:
"An identity and access control policy management application running
on the remote device is affected by an unauthorized access
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and installed patches,
the remote Cisco Identity Services Engine (ISE) application running
on the remote device is affected by an unspecified flaw in the Admin
portal that allows unauthorized access. An unauthenticated, remote
attacker can exploit this issue to obtain complete control of the
device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160113-ise
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59e15877");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuw34253");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch referenced in Cisco Security Advisory
cisco-sa-20160113-ise.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

appname = "Cisco ISE";
version = get_kb_item_or_exit("Host/Cisco/ISE/version");
patches = get_kb_item("Host/Cisco/ISE/patches");

patch_fix   = NULL;
patch_detected = FALSE;

if      (version =~ "^1\.2\.0($|[^0-9])") patch_fix = '17';
else if (version =~ "^1\.2\.1($|[^0-9])") patch_fix = '8';
else if (version =~ "^1\.3($|[^0-9])")    patch_fix = '5';
else if (version =~ "^1\.4($|[^0-9])")    patch_fix = '4';
else
  audit(AUDIT_INST_VER_NOT_VULN, appname, version);

if (!empty_or_null(patches))
{
  patches = split(patches, sep:', ', keep:FALSE);
  foreach patch (patches)
    if (patch == patch_fix) patch_detected = TRUE;
}

if (patch_detected)
  audit(AUDIT_INST_VER_NOT_VULN, appname, version + " with patch " + patch_fix);

security_report_cisco(
  port     : 0,
  severity : SECURITY_HOLE,
  version  : version,
  bug_id   : "CSCuw34253",
  pie      : patch_fix,
  override : FALSE
);
