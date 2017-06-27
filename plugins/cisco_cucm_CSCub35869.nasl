#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70089);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/04/03 04:40:26 $");

  script_cve_id("CVE-2013-3461");
  script_bugtraq_id(61908);
  script_osvdb_id(96490);
  script_xref(name:"CISCO-BUG-ID", value:"CSCub35869");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130821-cucm");

  script_name(english:"Cisco Unified Communications Manager SIP DoS (CSCub85597)");
  script_summary(english:"Checks the version of Cisco Unified Communications Manager (CUCM).");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Cisco Unified
Communications Manager (CUCM) device insufficiently limits the rate of
traffic on the session initiation protocol (SIP) port, allowing an
attacker to cause a denial of service condition by sending UDP packets
at high rates to that port.");
  # http://tools.cisco.com/security/center/viewAlert.x?alertId=30433
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ccddc990");

  script_set_attribute(attribute:"solution", value:
"For Cisco Unified Communications Manager 8.6(x), upgrade to 8.6(2a)su3
or later. For 9.x, upgrade to 9.1(2) or later. For 8.5(x), refer to
the vendor for a fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ucm_detect.nbin", "sip_detection.nasl");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display", "Services/udp/sip");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver         = get_kb_item_or_exit("Host/Cisco/CUCM/Version");
ver_display = get_kb_item_or_exit("Host/Cisco/CUCM/Version_Display");

sip_ports = get_kb_list_or_exit("Services/udp/sip");
app_name  = "Cisco Unified Communications Manager (CUCM)";
fixed_ver = NULL;

# Bulletin claims all 8.5(x) are vulnerable.
if (ver =~ "^8\.5\.")
  fixed_ver = "Refer to the vendor.";
else if (ver =~ "^8\.6\." && ver_compare(ver:ver, fix:"8.6.2.23900.10", strict:FALSE) < 0)
  fixed_ver = "8.6(2a)su3";
# Cisco's recommended version differs from the first fixed version.
# We check against the first fix, but recommend what Cisco recommends
# if the target is found vulnerable.
else if (ver =~ "^9\." && ver_compare(ver:ver, fix:"9.1.1.10000.36", strict:FALSE) < 0)
  fixed_ver = "9.1(2)";
else
  audit(AUDIT_INST_VER_NOT_VULN, app_name, ver);

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : CSCub35869'     +
    '\n  Installed release : ' + ver_display +
    '\n  Fixed release     : ' + fixed_ver   +
    '\n';
}

foreach port (sip_ports)
{
  if (report_verbosity > 0)
    security_hole(port:port, proto:"udp", extra:report);
  else
    security_hole(port:port, proto:"udp");
}
