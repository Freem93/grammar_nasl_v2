#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78586);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/16 14:22:05 $");

  script_cve_id("CVE-2014-0224");
  script_bugtraq_id(67899);
  script_osvdb_id(107729);
  script_xref(name:"CERT", value:"978508");

  script_name(english:"Palo Alto Networks PAN-OS < 5.0.14 / 5.1.x < 5.1.9 / 6.0.x < 6.0.4 OpenSSL MitM");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a man-in-the-middle vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Palo Alto Networks PAN-OS
prior to 5.0.14 / 5.1.9 / 6.0.4. It is, therefore, affected by a flaw
in the included OpenSSL library that can cause the client or server to
use weak keying material, which a remote attacker can exploit to
conduct a man-in-the-middle attack.");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/23");
  script_set_attribute(attribute:"solution", value:"Upgrade to PAN-OS version 5.0.14 / 5.1.9 / 6.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Palo Alto Networks PAN-OS";
version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Version");
full_version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Full_Version");
fix = NULL;

# Ensure sufficient granularity.
if (version !~ "^\d+\.\d+") audit(AUDIT_VER_NOT_GRANULAR, app_name, full_version);

if (version =~ "^5\.1($|[^0-9])")
  fix = "5.1.9";
else if (version =~ "^6\.0($|[^0-9])")
  fix = "6.0.4";
else
  fix = "5.0.14";

# Compare version to fix and report as needed.
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + full_version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(extra:report, port:0);
  }
  else security_warning(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);
