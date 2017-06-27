#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70124);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/04/24 19:17:52 $");

  script_cve_id(
    "CVE-2013-1102",
    "CVE-2013-1103",
    "CVE-2013-1104",
    "CVE-2013-1105"
  );
  script_bugtraq_id(57524);
  script_osvdb_id(89530, 89531, 89532, 89533);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtx80743");
  script_xref(name:"CISCO-BUG-ID", value:"CSCts87659");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuc15636");
  script_xref(name:"CISCO-BUG-ID", value:"CSCua60653");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130123-wlc");

  script_name(english:"Multiple Vulnerabilities in Cisco Wireless LAN Controllers (cisco-sa-20130123-wlc)");
  script_summary(english:"Checks the WLC version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Cisco Wireless LAN Controller (WLC) is affected by one or
more of the following vulnerabilities :

  - Wireless Intrusion Prevention System (wIPS) Denial of
    Service Vulnerability (CSCtx80743)

  - Session Initiation Protocol Denial of Service
    Vulnerability (CSCts87659)

  - Remote Code Execution Vulnerability (CSCuc15636)

  - SNMP Unauthorized Access Vulnerability (CSCua60653)"
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130123-wlc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a2a80eb");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130123-wlc."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

version = get_kb_item_or_exit("Host/Cisco/WLC/Version");
model = get_kb_item_or_exit("Host/Cisco/WLC/Model");

if (
  model !~ "(^|[^0-9])20\d\d($|[^0-9])" &&
  model !~ "(^|[^0-9])21\d\d($|[^0-9])" &&
  model !~ "(^|[^0-9])25\d\d($|[^0-9])" &&
  model !~ "(^|[^0-9])41\d\d($|[^0-9])" &&
  model !~ "(^|[^0-9])44\d\d($|[^0-9])" &&
  model !~ "(^|[^0-9])55\d\d($|[^0-9])" &&
  model !~ "(^|[^0-9])75\d\d($|[^0-9])" &&
  model !~ "(^|[^0-9])85\d\d($|[^0-9])" &&
  "AIR-WLC" >!< model
) audit(AUDIT_HOST_NOT, "affected");

fixed_version = "";
if (version =~ "^7\.0\." && ver_compare(ver:version, fix:"7.0.235.3") == -1) fixed_version = "7.0.235.3";
else if (version =~ "^7\.1($|[^0-9])") fixed_version = "7.2 or later";
else if (version =~ "^7\.2\." && ver_compare(ver:version, fix:"7.2.111.3") == -1) fixed_version = "7.2.111.3";
else if (version =~ "^7\.3\." && ver_compare(ver:version, fix:"7.3.112.0") == -1) fixed_version = "7.3.112.0";
else audit(AUDIT_HOST_NOT, "affected");

if (report_verbosity > 0)
{
  report =
    '\n  Model             : ' + model +
    '\n  Installed Version : ' + version +
    '\n  Fixed version     : ' + fixed_version +
    '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
