#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83466);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/04/27 19:46:26 $");

  script_cve_id("CVE-2015-0715");
  script_bugtraq_id(74473);
  script_osvdb_id(121724);
  script_xref(name:"CISCO-BUG-ID", value:"CSCut33447");
  script_xref(name:"CISCO-BUG-ID", value:"CSCut33608");

  script_name(english:"Cisco Unified Communications Manager SQL Injection (CSCut33447 / CSCut33608)");
  script_summary(english:"Checks the version of Cisco Unified Communications Manager (CUCM).");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by several SQL injection vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Cisco Unified
Communications Manager (CUCM) device is affected by multiple SQL
injection vulnerabilities due to improper validation of user-supplied
input. An authenticated, remote attacker can exploit these issues to
inject or modify SQL queries, resulting in the manipulation or
disclosure of sensitive data.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=38674");
  script_set_attribute(attribute:"solution", value:
"Contact Cisco support in order to obtain a fixed version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver         = get_kb_item_or_exit("Host/Cisco/CUCM/Version");
ver_display = get_kb_item_or_exit("Host/Cisco/CUCM/Version_Display");

app_name  = "Cisco Unified Communications Manager (CUCM)";

if (ver != "11.0.0.98000.225")
  audit(AUDIT_INST_VER_NOT_VULN, app_name, ver_display);

fixed_ver = "11.0.0.98000-273";
set_kb_item(name: 'www/0/SQLInjection', value: TRUE);

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : CSCut33447 / CSCut33608' +
    '\n  Installed release : ' + ver_display +
    '\n  Fixed release     : ' + fixed_ver   +
    '\n';

  security_warning(port:0, extra:report);
}
else security_warning(0);
exit(0);
