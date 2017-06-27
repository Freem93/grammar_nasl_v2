#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85895);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id("CVE-2015-4271");
  script_bugtraq_id(75939);
  script_osvdb_id(124754);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv00604");

  script_name(english:"Cisco TelePresence TC Software Parameter Authentication Bypass (CSCuv00604)");
  script_summary(english:"Checks the software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco TelePresence TC software running on the remote
host is affected by an unspecified flaw due to improper validation of
user-supplied input. An unauthenticated, remote attacker can exploit
this to bypass authentication mechanisms by sending multiple request
parameters to the affected host.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=39880");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch referenced in Cisco bug ID CSCuv00604.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_tc_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_mcu_detect.nasl");
  script_require_keys("Cisco/TelePresence_MCU/Device", "Cisco/TelePresence_MCU/Version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Cisco TelePresence TC software";
device = get_kb_item_or_exit("Cisco/TelePresence_MCU/Device");
version = get_kb_item_or_exit("Cisco/TelePresence_MCU/Version");

# Integrator C Series only :
# TelePresence Codec C90
# TelePresence Codec C60
# TelePresence Codec C40
# TelePresence System Integrator Package C90
# TelePresence System Integrator Package C60
# TelePresence System Integrator Package C40
# TelePresence System Quick Set C20
if (
  device !~ " C20($|[ \n\r])" &&
  device !~ " C40($|[ \n\r])" &&
  device !~ " C60($|[ \n\r])" &&
  device !~ " C90($|[ \n\r])"
) audit(AUDIT_HOST_NOT, "an affected Cisco TelePresence device");

short_version = eregmatch(pattern: "^TC(\d+(?:\.\d+)*)", string:version);
if (isnull(short_version))
  audit(AUDIT_UNKNOWN_APP_VER, app_name);
else
  short_version = short_version[1];

if (short_version =~ "^7(\.3)?$") audit(AUDIT_VER_NOT_GRANULAR, app_name, short_version);
if (short_version !~ "^7\.3\.") audit(AUDIT_HOST_NOT, "running version 7.3.x");

if (ver_compare(ver:short_version, fix:'7.3.4', strict:FALSE) == -1)
{
  port = 0;
  if (report_verbosity > 0)
  {
    report = '\n  Detected version : ' + version +
             '\n  Fixed version    : See solution.' +
             '\n  Cisco bug ID     : CSCuv00604' +
             '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
