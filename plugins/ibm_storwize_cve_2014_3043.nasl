#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76767);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/06/28 04:36:42 $");

  script_cve_id("CVE-2014-3043");
  script_bugtraq_id(68698);
  script_osvdb_id(109227);

  script_name(english:"IBM Storwize V7000 Unified Service Account Unspecified Local Privilege Escalation");
  script_summary(english:"Checks for vulnerable Storwize models.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an unspecified local privilege
escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by an unspecified local privilege
escalation vulnerability that can be exploited through an IBM service
account on the device.

Note that Nessus has not checked if the remote device has been
patched. The device should be checked manually to confirm if the host
is vulnerable.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=ssg1S1004811");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.4.3.3 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:ibm:storwize_unified_v7000");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:storwize_unified_v7000_software");
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

fix = "1.4.3.3";

# audit out if it isn't an affected device
if (
  machine_major != "2073" # V7000 Unified
) audit(AUDIT_DEVICE_NOT_VULN, display_name);

if (version == "Unknown")
{
  # If we don't have version info, exit unless it's a paranoid scan
  if (report_paranoia < 2) audit(AUDIT_PARANOID);
}
else
{
  # If we have version info
  if (version !~ "^1\.[3-4]\.") audit(AUDIT_DEVICE_NOT_VULN, display_name, version);

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
  security_warning(port:0, extra:report);
}
else security_warning(port:0);
