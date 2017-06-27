#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72828);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/06/17 19:25:32 $");

  script_bugtraq_id(64627);

  script_name(english:"Palo Alto Networks PAN-OS 5.0.9 Multiple Vulnerabilities");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running version 5.0.9 of Palo Alto Networks PAN-OS.
It is, therefore, affected by multiple vulnerabilities :

  - A denial of service vulnerability exists due to an
    inability to handle IP packets larger than 1480 bytes
    through an Active/Active VWire setup. An attacker can
    exploit this vulnerability to cause packet loss.
    (Ref# 56153)

  - A security bypass vulnerability exists due to a flaw in
    Zone Protection when SYN Cookie is enabled. An attacker
    can exploit this vulnerability to evade IP spoofing
    checks. (Ref# 57059)

  - A security bypass vulnerability exists due to a flaw in
    session management when using Global Protect pre-logon
    mode. (Ref# 58539)"
  );
  script_set_attribute(attribute:"see_also", value:"https://live.paloaltonetworks.com/docs/DOC-6386");
  script_set_attribute(attribute:"solution", value:"Upgrade to PAN-OS version 5.0.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/05");

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
vuln = '5.0.9';
fix = '5.0.10';

# Ensure sufficient granularity.
if (version !~ "^\d+\.\d+") audit(AUDIT_VER_NOT_GRANULAR, app_name, full_version);

# Compare version to vuln and report as needed.
if (ver_compare(ver:version, fix:vuln, strict:FALSE) == 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + full_version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_note(extra:report, port:0);
  }
  else security_note(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);
