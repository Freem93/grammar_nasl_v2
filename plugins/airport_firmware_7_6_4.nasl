#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(69817);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/09/09 23:50:19 $");

  script_cve_id("CVE-2013-5132");
  script_bugtraq_id(62262);
  script_osvdb_id(97036);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-09-06-1");

  script_name(english:"Apple AirPort Base Station (802.11n) Firmware < 7.6.4 Remote DoS (APPLE-SA-2013-09-06-1)");
  script_summary(english:"Checks firmware version through SNMP");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote network device is affected by a denial of service
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the firmware version collected via SNMP, the remote
AirPort Extreme Base Station / AirPort Express Base Station / Apple
Time Capsule reportedly does not properly parse small frames with
incorrect lengths.  An associated client might be able to leverage
this vulnerability to cause a termination of the base station system."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5920");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Sep/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/528462/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade the firmware to version 7.6.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("snmp_airport_version.nasl");
  script_require_keys("Host/Airport/Firmware", "SNMP/community");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");



version = get_kb_item_or_exit("Host/Airport/Firmware");
fixed_version = "7.6.4";

if (
  ver_compare(ver:version, fix:"7.0.0", strict:FALSE) >= 0  &&
  ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The host is not affected since firmware version " + version + " is installed.");
