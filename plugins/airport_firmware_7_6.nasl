#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56855);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/10/17 13:39:34 $");

  script_cve_id("CVE-2011-0997");
  script_bugtraq_id(47176);
  script_osvdb_id(71493);

  script_name(english:"Apple Time Capsule and AirPort Base Station (802.11n) Firmware < 7.6 (APPLE-SA-2011-11-10-2)");
  script_summary(english:"Checks firmware version through SNMP");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote network device is affected by an arbitrary code execution
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the firmware version collected via SNMP, the copy of
dhclient-script included with the remote Apple Time Capsule / AirPort
Express Base Station / AirPort Extreme Base Station reportedly fails
to strip shell meta-characters in a hostname obtained from a DHCP
response.  A remote attacker might be able to leverage this
vulnerability to execute arbitrary code on the affected device."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT5005"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2011/Nov/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/520482/30/0/threaded"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the firmware to version 7.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("snmp_airport_version.nasl");
  script_require_keys("Host/Airport/Firmware", "SNMP/community");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");



version = get_kb_item_or_exit("Host/Airport/Firmware");
fixed_version = "7.6";

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
else exit(0, "The host is not affected since it has firmware version " + version + " is installed.");
