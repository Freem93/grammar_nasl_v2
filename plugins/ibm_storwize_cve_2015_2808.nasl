#

include("compat.inc");

if (description)
{
  script_id(91633);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/23 14:38:50 $");

  script_cve_id("CVE-2015-2808");
  script_bugtraq_id(73684);
  script_osvdb_id(117855);

  script_name(english:"IBM Storwize SSL/TLS RC4 Stream Cipher Key Invariance (Bar Mitzvah)");
  script_summary(english:"Checks for vulnerable Storwize models.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a security feature bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the IBM Storwize server
running on the remote host is affected by a security feature bypass
vulnerability, known as Bar Mitzvah, due to improper combination of
state data with key data by the RC4 cipher algorithm during the
initialization phase. A man-in-the-middle attacker can exploit this,
via a brute-force attack using LSB values, to decrypt the traffic.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://www.blackhat.com/docs/asia-15/materials/asia-15-Mantin-Bar-Mitzvah-Attack-Breaking-SSL-With-13-Year-Old-RC4-Weakness-wp.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4bbf45ac");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=ssg1S1005213");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=ssg1S1005210");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Storwize version 1.5.2.0 / 7.3.0.10 / 7.4.0.4 / or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:ibm:storwize_v7000_unified");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:ibm:storwize_v7000");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:ibm:storwize_v5000");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:ibm:storwize_v3700");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:ibm:storwize_v3500");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:ibm:san_volume_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:storwize_v7000_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:storwize_v5000_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:storwize_v3700_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:storwize_v3500_software");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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
  machine_major != "2073" && # Storwize V7000 Unified";
  machine_major != "2076" && # V7000
  machine_major != "2071" && # V3500
  machine_major != "2077" && # V5000
  machine_major != "2072" && # V3700
  machine_major != "2145"    # SAN Volume Controller
) audit(AUDIT_DEVICE_NOT_VULN, display_name);

if (version == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_APP_VER, display_name);

# Versions 1.1 thru 7.4 are affected
# 7.4.0.4 and 7.3.0.10 are fixed for non-Unified versions
# 1.5.2.0 is fixed for Unified
if (machine_major != "2073")
{
  if (version =~ "^(1\.[1-9][0-9]*\.|[2-6]\.|7\.[0-2]\.)")
    fix = "7.3.0.10 or 7.4.0.4";
  else if (version =~ "^7\.3\." && ver_compare(ver:version, fix:"7.3.0.10") < 0)
    fix = "7.3.0.10";
  else if (version =~ "^7\.4\." && ver_compare(ver:version, fix:"7.4.0.4") < 0)
    fix = "7.4.0.4";
  else audit(AUDIT_DEVICE_NOT_VULN, display_name, version);
}
else
{
  if (version =~ "^1\.[3-5]\." && ver_compare(ver:version, fix:"1.5.2.0") < 0)
    fix = "1.5.2.0";
  else audit(AUDIT_DEVICE_NOT_VULN, display_name, version);
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
