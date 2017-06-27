#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69987);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id("CVE-2012-2131", "CVE-2013-0166", "CVE-2013-0169");
  script_bugtraq_id(53212, 57778, 60268);
  script_osvdb_id(82110, 89848, 89865);

  script_name(english:"Junos Pulse Secure IVE / UAC OS Multiple SSL Vulnerabilities");
  script_summary(english:"Checks IVE/UAC OS version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the version of IVE / UAC OS
running on the remote host may be affected by multiple vulnerabilities :

  - Remote attackers may be able to trigger buffer overflow
    vulnerabilities on the OpenSSL libraries by sending
    specially crafted DER data, resulting in memory
    corruption. (CVE-2012-2131)

  - A weakness in the OpenSSL library leaves it vulnerable
    to an attack that could allow a third party to recover
    (fully or partially) the plaintext from encrypted
    traffic. (CVE-2013-0169)

  - A flaw in OCSP signature verification in the OpenSSL
    library allows remote OCSP servers to cause a denial of
    service condition with an invalid key. (CVE-2013-0166)"
  );
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10591");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Juniper IVE/UAC OS version 7.1r15 / 7.2r11 / 7.3r6 / 7.4r3 /
4.1r8.1 / 4.2r5.1 / 4.3r6 / 4.4r3 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:ive_os");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_pulse_access_control_service");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_pulse_secure_access_service");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Juniper/IVE OS/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit('Host/Juniper/IVE OS/Version');
match = eregmatch(string:version, pattern:"^([\d.]+)[Rr]([0-9.]+)");
if (isnull(match)) exit(1, 'Error parsing version: ' + version);

release = match[1];
build = match[2];

# check report paranoia settings in order to avoid false positives,
# since a workaround is possible, and only devices with SSL acceleration
# cards are vulnerable
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = '';

# IVE-SA
if (release == '7.1' && ver_compare(ver:build, fix:'15', strict:FALSE) == -1)
  fix = '7.1r15';
if (release == '7.2' && ver_compare(ver:build, fix:'11', strict:FALSE) == -1)
  fix = '7.2r11';
if (release == '7.3' && ver_compare(ver:build, fix:'6', strict:FALSE) == -1)
  fix = '7.3r6';
if (release == '7.4' && ver_compare(ver:build, fix:'3', strict:FALSE) == -1)
  fix = '7.4r3';

# IVE-IC (UAC OS)
if (release == '4.1' && ver_compare(ver:build, fix:'8.1', strict:FALSE) == -1)
  fix = '4.1r8.1';
if (release == '4.2' && ver_compare(ver:build, fix:'5.1', strict:FALSE) == -1)
  fix = '4.2r5.1';
if (release == '4.3' && ver_compare(ver:build, fix:'6', strict:FALSE) == -1)
  fix = '4.3r6';
if (release == '4.4' && ver_compare(ver:build, fix:'3', strict:FALSE) == -1)
  fix = '4.4r3';

if (fix != '')
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'IVE/UAC OS', version);
