#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70123);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/04/24 19:17:52 $");

  script_cve_id(
    "CVE-2009-1164",
    "CVE-2009-1165",
    "CVE-2009-1166",
    "CVE-2009-1167"
  );
  script_bugtraq_id(35805, 35817, 35818, 35819);
  script_osvdb_id(56700, 56701, 56702, 56703);
  script_xref(name:"CISCO-BUG-ID", value:"CSXsx03715");
  script_xref(name:"IAVT", value:"2009-T-0044");
  script_xref(name:"CISCO-BUG-ID", value:"CSCsw40789");
  script_xref(name:"CISCO-BUG-ID", value:"CSCsy27708");
  script_xref(name:"CISCO-BUG-ID", value:"CSCsy44672");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20090727-wlc");

  script_name(english:"Multiple Vulnerabilities in Cisco Wireless LAN Controllers (cisco-sa-20090727-wlc)");
  script_summary(english:"Checks the WLC version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Cisco Wireless LAN Controller (WLC) is affected by one or
more of the following vulnerabilities:

  - Malformed HTTP or HTTPS authentication response Denial
    of Service (CVE-2009-1164)

  - SSH connections Denial of Service (CVE-2009-1165)

  - Crafted HTTP or HTTPS request Denial of Service
    (CVE-2009-1166)

  - Crafted HTTP or HTTPS request unauthorized configuration
    modification vulnerability (CVE-2009-1167)"
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20090727-wlc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3a4ba9c");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20090727-wlc."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  model !~ "15\d\d" &&
  model !~ "20\d\d" &&
  model !~ "21\d\d" &&
  model !~ "41\d\d" &&
  model !~ "42\d\d" &&
  model !~ "44\d\d"
) audit(AUDIT_HOST_NOT, "affected");

fixed_version = "";
if (version =~ "^3\.2" && ver_compare(ver:version, fix:"3.2.215.0") == -1) fixed_version = "3.2.215.0";
else if (version =~ "^4\.1") fixed_version = "4.2 or later";
else if (version =~ "^4\.1.*M") fixed_version = "5.2, 6.0, or 4.2M";
else if (version =~ "^4\.2" && ver_compare(ver:version, fix:"4.2.205.0") == -1) fixed_version = "4.2.205.0";
else if (version =~ "^5\.0") fixed_version = "5.2 or 6.0";
else if (version =~ "^5\.1") fixed_version = "5.2 or 6.0";
else if (version =~ "^5\.2" && ver_compare(ver:version, fix:"5.2.191.0") == -1) fixed_version = "5.2.191.0";
else audit(AUDIT_HOST_NOT, "affected");

if (report_verbosity > 0)
{
  report =
    '\n  Model             : ' + model +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version +
    '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
