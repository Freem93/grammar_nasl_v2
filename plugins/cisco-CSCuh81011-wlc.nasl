#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71173);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id("CVE-2013-6684");
  script_bugtraq_id(63684);
  script_osvdb_id(99750);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh81011");

  script_name(english:"HTTP DoS Vulnerability in Cisco Wireless LAN Controllers");
  script_summary(english:"Checks the WLC version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security update.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote Cisco Wireless LAN Controller (WLC) is affected by a denial
of service vulnerability related to handling HTTP requests containing
unspecified configuration parameters."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-6684
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa1311eb");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=31743");
  script_set_attribute(attribute:"solution", value:"Upgrade to 7.6(1.120), 8.0(72.64), or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/03");

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

if (model !~ "55\d\d") audit(AUDIT_HOST_NOT, "Model 55xx");

fixed_version = "";
if (version =~ "^[3-7]\." && ver_compare(ver:version, fix:"7.6.1.120", strict:FALSE) < 0) fixed_version = "7.6.1.120";
else if (version =~ "^8\.0" && ver_compare(ver:version, fix:"8.0.72.64", strict:FALSE) < 0) fixed_version = "8.0.72.64";
else audit(AUDIT_HOST_NOT, "affected");

if (report_verbosity > 0)
{
  report =
    '\n  Model             : ' + model +
    '\n  Installed Version : ' + version +
    '\n  Fixed version     : ' + fixed_version +
    '\n';
  security_warning(port:0, extra:report);
}
else security_warning(0);
