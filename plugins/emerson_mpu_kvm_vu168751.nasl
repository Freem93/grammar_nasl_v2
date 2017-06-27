#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72336);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/02/10 16:28:33 $");

  script_cve_id("CVE-2013-6030");
  script_bugtraq_id(65105);
  script_osvdb_id(102408);
  script_xref(name:"CERT", value:"168751");

  script_name(english:"Emerson Network Power Avocent MergePoint Unity KVM Switch < 1.14 / 1.18 download.php filename Parameter Directory Traversal");
  script_summary(english:"Checks MPU KVM switch version");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a directory traversal vulnerability.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is an Emerson Network Power Avocent MergePoint Unity
KVM Switch with a firmware version prior to 1.14 or 1.18.  It is,
therefore, affected by a directory traversal vulnerability due to a
failure to sanitize user-supplied input to the 'filename' parameter of
the 'download.php' script.  An authenticated attacker can potentially
exploit this vulnerability to gain access to arbitrary files."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2014/Jan/162");
  # http://www.avocent.com/Support_Firmware/MergePoint_Unity/MergePoint_Unity_Switch.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42d403b9");
  script_set_attribute(attribute:"solution", value:"Upgrade to firmware version 1.14 / 1.18, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:emerson:network_power_avocent_mergepoint_unity");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("emerson_mpu_kvm_detect.nbin");
  script_require_keys("Host/Emerson/MPU/Model", "Host/Emerson/MPU/Version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

model = get_kb_item_or_exit("Host/Emerson/MPU/Model");
version = get_kb_item_or_exit("Host/Emerson/MPU/Version");

product_name = "Emerson Network Power Avocent MergePoint Unity KVM Switch";
firmware_name = "MergePoint Unity Firmware";

# Make sure we know the version number.
if (version =~ "^Unknown$") audit(AUDIT_UNKNOWN_APP_VER, firmware_name);

# Make sure we have at least a major and minor version.
if (version !~ "^(\d+\.)+\d+$") audit(AUDIT_VER_NOT_GRANULAR, firmware_name, version);

# Version check and report.
min = "1.2";
fix = "1.14";
if (
  ver_compare(ver:version, fix:min, strict:FALSE) >= 0 &&
  ver_compare(ver:version, fix:fix, strict:FALSE) == -1
)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  KVM switch model           : ' + model +
    '\n  Installed firmware version : ' + version +
    '\n  Fixed firmware version     : ' + fix +
    '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, firmware_name, version);
