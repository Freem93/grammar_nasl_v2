#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86186);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/03 20:51:50 $");

  script_cve_id("CVE-2015-6531");
  script_osvdb_id(127526);
  script_xref(name:"TRA", value:"TRA-2015-02");

  script_name(english:"Palo Alto Networks Panorama PAN-OS < 6.0.1 Firmware Signature Verification Bypass Arbitrary Code Execution");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a firmware signature bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Panorama appliance is running a version of Palo Alto
Networks PAN-OS prior to 6.0.1. It is, therefore, affected by a
firmware signature bypass vulnerability due to a flaw in signature
verification process that allows an attacker to execute arbitrary
Python code within an image file before the signature is verified.
Exploitation of this issue requires convincing an administrator to
install a file from a malicious source (e.g. social engineering,
hosting on a phishing site, or a man-in-the-middle attack on a
legitimate download). ");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2015-02");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 6.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");

if (!get_kb_item("Host/local_checks_enabled"))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

app_name = "Palo Alto Networks Panorama";
version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Version");
model = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Model");
fix = FALSE;

if(model != "Panorama")
  audit(AUDIT_HOST_NOT, "a Palo Alto Panorama model");

item = eregmatch(pattern:"^([\d.]+)([^\d.]|$)", string:version);
if(isnull(item[1]))
  exit(1, "Unable to parse version string " + version + ".");
  
version = item[1];

fix = "6.0.1";
if(ver_compare(fix:fix, ver:version, strict:FALSE) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed versions    : ' + fix +
    '\n';
  security_hole(extra:report, port:0);
}
else security_hole(0);
