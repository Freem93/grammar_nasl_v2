#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88102);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/04/24 19:17:53 $");

  script_cve_id("CVE-2015-6341");
  script_bugtraq_id(77119);
  script_osvdb_id(129027);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151016-wlc");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw10610");

  script_name(english:"Cisco Wireless LAN Controller Client Disconnection DoS");
  script_summary(english:"Checks the WLC version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security update.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Wireless LAN Controller (WLC) is affected by a denial
of service vulnerability due to the lack of access control to the
management GUI. An unauthenticated, remote attacker can exploit this
to trigger client disconnections.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151016-wlc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60909734");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCuw10610, or
contact the vendor regarding patch options.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/Cisco/WLC/Version");

######################
# Known Affected :
# 7.4(140.0)
# 7.6(130.0)
# 8.0(120.0)
######################
# Known Fixed :
# 8.0(120.15)
######################

fixed_version = "";
if (version == "7.4.140.0") fixed_version = "See Advisory";
else if (version == "7.6.130.0") fixed_version = "See Advisory";
else if (version == "8.0.120.0") fixed_version = "8.0.120.15";
else audit(AUDIT_HOST_NOT, "affected");

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version +
    '\n';
  security_warning(port:0, extra:report);
}
else security_warning(0);
