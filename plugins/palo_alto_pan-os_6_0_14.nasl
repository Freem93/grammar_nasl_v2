#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93126);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_osvdb_id(
    141159,
    141160,
    141161
  );

  script_name(english:"Palo Alto Networks PAN-OS 6.0.x < 6.0.14 Multiple Vulnerabilities");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Palo Alto Networks PAN-OS running on the remote host is
6.0.x prior to 6.0.14. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified flaw exists that allows an authenticated,
    remote attacker to gain elevated privileges.
    (VulnDB 141159)

  - An unspecified flaw exists in the policy configuration
    dialog that allows an authenticated, remote attacker to
    have an unspecified impact. (VulnDB 141160)

  - A boundary check error exists in the Captive Portal that
    allows a remote attacker to cause a denial of service.
    (VulnDB 141161)");
  # https://www.paloaltonetworks.com/documentation/60/pan-os/pan-os-6-0-release-notes/pan-os-6-0-14-addressed-issues
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?37d0a0a0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 6.0.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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
fix = '6.0.14';

# Ensure sufficient granularity.
if (version !~ "^\d+\.\d+") audit(AUDIT_VER_NOT_GRANULAR, app_name, full_version);

# 6.0.x is affected.
if (version !~ "^6\.0($|[^0-9])") audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);

# Compare version to vuln and report as needed.
if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Installed version : ' + full_version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(severity:SECURITY_HOLE, extra:report, port:0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);
