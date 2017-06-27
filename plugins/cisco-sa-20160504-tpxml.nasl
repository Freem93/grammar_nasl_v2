#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91130);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/04 15:59:51 $");

  script_cve_id("CVE-2016-1387");
  script_osvdb_id(138025);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz26935");
  script_xref(name:"IAVA", value:"2016-A-0132");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160504-tpxml");

  script_name(english:"Cisco TelePresence XML API HTTP Request Handling Authentication Bypass (cisco-sa-20160504-tpxml)");
  script_summary(english:"Checks the software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Cisco TelePresence Codec (TC)
that is 7.2.x prior to 7.3.6 or a version of Cisco Collaboration
Endpoint (CE) software that is 8.x prior 8.1.1. It is, therefore,
affected by an authentication bypass vulnerability in the XML
application programming interface (API) of Cisco TC or Cisco CE due to
improper implementation of authentication mechanisms for the XML API.
An unauthenticated, remote attacker can exploit this, via a crafted
HTTP request to the XML API, to bypass authentication and perform
unauthorized configuration changes or issue control commands.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160504-tpxml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4e80bb3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco TelePresence Codec (TC) version 7.3.6 or Cisco
Collaboration Endpoint (CE) version 8.1.1. Alternatively, apply the
workaround referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_tc_software");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:telepresence_ce_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_mcu_detect.nasl");
  script_require_keys("Cisco/TelePresence_MCU/Device", "Cisco/TelePresence_MCU/Version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Cisco TelePresence TC/CE software";
device = get_kb_item_or_exit("Cisco/TelePresence_MCU/Device");
version = get_kb_item_or_exit("Cisco/TelePresence_MCU/Version");
flag = FALSE;

# Affected models:
# TelePresence EX Series
# TelePresence Integrator C Series
# TelePresence MX Series
# TelePresence Profile Series
# TelePresence SX Series
# TelePresence SX Quick Set Series
# TelePresence VX Clinical Assistant
# TelePresence VX Tactical
# Note: VX Tactical/Clinical identify as SX20
if (
  device !~ " C[2469]0($|[ \n\r])" &&
  device !~ " EX[69]0($|[ \n\r])" &&
  device !~ " MX[2378]00(\sG2)?($|[ \n\r])" &&
  device !~ " Profile.+($|[ \n\r])" &&
  device !~ " SX[128]0($|[ \n\r])"
) audit(AUDIT_HOST_NOT, "an affected Cisco TelePresence device");

# Based on headers returned during testing/research, TC is upper-case
# and ce is lowercase in the SoftW: section of the header. 
short_version = eregmatch(pattern: "^(TC|ce)(\d+(?:\.\d+){0,2})", string:version);
if (isnull(short_version))
  audit(AUDIT_NOT_DETECT, app_name);
else{
  short_type = short_version[1];
  short_num = short_version[2];
}

if(short_type == "TC"){
  if (short_num =~ "^7(\.3)?$") audit(AUDIT_VER_NOT_GRANULAR, app_name, version);
  if (short_num =~ "^7\.[23]" && ver_compare(ver:short_num, fix:'7.3.6', strict:FALSE) < 0)
    flag = TRUE;
}
else if (short_type == "ce"){
  if (short_num =~ "^8(\.1)?$") audit(AUDIT_VER_NOT_GRANULAR, app_name, version);
  if (short_num =~ "^8\." && ver_compare(ver:short_num, fix:'8.1.1', strict:FALSE) < 0)
    flag = TRUE;
}
else audit(AUDIT_NOT_DETECT, app_name);

if (flag)
{
  # Paranoid because we can't be sure XML API is running
  # or isn't disabled, as per workaround in advisory
  if (report_paranoia < 2) audit(AUDIT_PARANOID);

  port = 0;

  report = '\n  Detected version : ' + version +
           '\n  Fixed version    : See solution.' +
           '\n  Cisco bug ID     : CSCuz26935' +
           '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
