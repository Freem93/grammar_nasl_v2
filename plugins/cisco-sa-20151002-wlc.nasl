#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92457);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/04/24 19:17:53 $");

  script_cve_id("CVE-2015-6311");
  script_bugtraq_id(76945);
  script_osvdb_id(128377);
  script_xref(name:"CISCO-SA", value:"Cisco-SA-20151002-CVE-2015-6311");
  script_xref(name:"CISCO-BUG-ID", value:"CSCub65236");

  script_name(english:"Cisco Wireless LAN Controller 802.11i Management Frame DoS");
  script_summary(english:"Checks the WLC version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing vendor-supplied security patches.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Cisco Wireless LAN
Controller (WLC) device is affected by a denial of service
vulnerability due to not discarding malformed values within an 802.11i
management frame received from a wireless client. An unauthenticated,
adjacent attacker can exploit this, by sending a specifically crafted
frame to an access point managed by the WLC device, to cause a denial
of service condition.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/Cisco-SA-20151002-CVE-2015-6311
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b72580b6");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patches referenced in Cisco bug ID CSCub65236.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

version = get_kb_item_or_exit("Host/Cisco/WLC/Version");
vuln = FALSE;

if (
  version == '7.0.240.0' ||
  version == '7.3.101.0' ||
  version == '7.4.1.19'
  ) vuln = TRUE;

if (!vuln) audit(AUDIT_HOST_NOT, "affected");

security_report_v4(
  port:0,
  severity:SECURITY_WARNING,
  extra:
    '\n  Cisco bug ID      : CSCub65236' +
    '\n  Installed version : ' + version +
    '\n'
);
