#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99985);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/04 19:15:02 $");

  script_cve_id("CVE-2017-3825");
  script_bugtraq_id(98293);
  script_osvdb_id(156924);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb95396");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170503-ctp");

  script_name(english:"Cisco TelePresence CE 8.1.1 < 8.3.2 ICMP Packet Handling DoS (cisco-sa-20170503-ctp)");
  script_summary(english:"Checks the software version.");

  script_set_attribute(attribute:"synopsis", value:
"A video conferencing application running on the remote host is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco TelePresence
Collaboration Endpoint (CE) software running on the remote host is
8.1.1 or later but prior to 8.3.2. It is, therefore, affected by a
denial of service vulnerability in the ICMP ingress packet processing
due to improper validation of the size of a received ICMP packet. An
unauthenticated, remote attacker can exploit this, via a specially
crafted ICMP packet, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170503-ctp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3b6864c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb95396");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Collaboration Endpoint (CE) version 8.3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:telepresence_ce_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_mcu_detect.nasl");
  script_require_keys("Cisco/TelePresence_MCU/Device", "Cisco/TelePresence_MCU/Version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Cisco TelePresence CE software";
device = get_kb_item_or_exit("Cisco/TelePresence_MCU/Device");
version = get_kb_item_or_exit("Cisco/TelePresence_MCU/Version");

# Affected models:
# Spark Room OS
# TelePresence MX Series
# TelePresence SX Quick Set Series
# TelePresence SX Series
# Quick set series are covered in the SX regex; SX10 and SX20 are quick set
if (
  device !~ " MX[2378]00(\sG2)?($|[ \n\r])" &&
  device !~ " SX[128]0($|[ \n\r])"
) audit(AUDIT_HOST_NOT, "an affected Cisco TelePresence device");

short_version = pregmatch(pattern: "^(ce|CE)(\d+(?:\.\d+){0,2})", string:version);
if (isnull(short_version))
  audit(AUDIT_NOT_DETECT, app_name);
else{
  short_num = short_version[2];
}

if (short_num =~ "^8(\.[123])?$") audit(AUDIT_VER_NOT_GRANULAR, app_name, version);
if (short_num =~ "^8\.[123]" && ver_compare(ver:short_num, minver:"8.1.1", fix:'8.3.2', strict:FALSE) < 0)
{

  port = 0;

  report = '\n  Detected version : ' + version +
           '\n  Fixed version    : See solution.' +
           '\n  Cisco bug ID     : CSCvb95396' +
           '\n';

  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
