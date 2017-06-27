#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76359);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/08/25 13:45:41 $");

  script_cve_id("CVE-2013-6737");
  script_bugtraq_id(68133);
  script_osvdb_id(108297);
  script_xref(name:"IAVA", value:"2014-A-0092");

  script_name(english:"IBM Storwize Authenticated Information Disclosure");
  script_summary(english:"Detects vulnerable Storwize Models.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Storwize device is a model that is affected by an
authenticated information disclosure vulnerability.

In the event of a hardware fault, memory contents containing customer
data may be written to a file that can be read by an authenticated
user of the system who may not otherwise have access to the data.

Note that Nessus has not checked if the remote device has been
patched. The device should be checked manually to confirm if the host
is vulnerable.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=ssg1S1004677");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=ssg1S1004676");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor's advisories.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:ibm:storwize_v7000");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:ibm:storwize_v5000");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:ibm:storwize_v3700");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:ibm:storwize_v3500");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:ibm:san_volume_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:storwize_v7000_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:storwize_v5000_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:storwize_v3700_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:storwize_v3500_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("ibm_storwize_detect.nbin");
  script_require_ports("Host/IBM/Storwize/version", "Host/IBM/Storwize/machine_major", "Host/IBM/Storwize/display_name");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/IBM/Storwize/version");
machine_major = get_kb_item_or_exit("Host/IBM/Storwize/machine_major");
display_name = get_kb_item_or_exit("Host/IBM/Storwize/display_name");

# audit out if it isn't an affected device
if (
  machine_major != "2071" && # V3500
  machine_major != "2072" && # V3700
  machine_major != "2076" && # V7000
  machine_major != "2077" && # V5000
  machine_major != "2145" && # SAN Volume Controller
  machine_major != "4939"    # Flex System V7000 Storage Node
) audit(AUDIT_DEVICE_NOT_VULN, display_name);

if (version == "Unknown")
{
  # If we don't have version info, exit unless it's a paranoid scan
  if (report_paranoia < 2) audit(AUDIT_PARANOID);
  fix = "6.4.1.7";
}
else
{
  # If we have version info:
  # All products are affected when running code releases 6.1, 6.2,
  # 6.3, 6.4 and 7.1 except for versions 6.4.1.7 and 7.1.0.7 and
  # above.
  if (
    version !~ "^6\.[1-4]\." &&
    version !~ "^7\.1\."
  ) audit(AUDIT_DEVICE_NOT_VULN, display_name, version);

  fix = "6.4.1.7";
  if (version =~ "^7\.1\.") fix = "7.1.0.7";

  if (ver_compare(ver:version, fix:fix, strict:FALSE) >= 0)
    audit(AUDIT_DEVICE_NOT_VULN, display_name, version);
}

if (report_verbosity > 0)
{
  report =
    '\n  Name              : ' + display_name +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_note(port:0, extra:report);
}
else security_note(port:0);
