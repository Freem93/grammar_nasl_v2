#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76131);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/04 18:02:13 $");

  script_cve_id("CVE-2014-0076", "CVE-2014-0224", "CVE-2014-3470");
  script_bugtraq_id(66363, 67898, 67899);
  script_osvdb_id(104810, 107729, 107731);
  script_xref(name:"CERT", value:"978508");

  script_name(english:"Cisco TelePresence MCU Series Devices Multiple Vulnerabilities in OpenSSL");
  script_summary(english:"Checks TelePresence MCU device version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco TelePresence MCU device is running a software version
known to be affected by multiple OpenSSL related vulnerabilities :

- An error exists related to the implementation of the
    Elliptic Curve Digital Signature Algorithm (ECDSA) that
    could allow nonce disclosure via the 'FLUSH+RELOAD'
    cache side-channel attack. (CVE-2014-0076)

  - An unspecified error exists that could allow an
    attacker to cause usage of weak keying material
    leading to simplified man-in-the-middle attacks.
    (CVE-2014-0224)

  - An unspecified error exists related to anonymous ECDH
    ciphersuites that could allow denial of service
    attacks. Note this issue only affects OpenSSL TLS
    clients. (CVE-2014-3470)");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140605-openssl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5539aa9d");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"solution", value:
"No known fixed version have been released. There are partial
workarounds detailed in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_mcu_mse_series_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_mcu_detect.nasl");
  script_require_keys("Cisco/TelePresence_MCU/Version", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

device = get_kb_item_or_exit("Cisco/TelePresence_MCU/Device");
version = get_kb_item_or_exit("Cisco/TelePresence_MCU/Version");

if (version !~ "^[0-9.()]+$") exit(0, 'The version string is invalid or not applicable.');

# only affected if HTTPS admin interface is enabled
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = '';
found_affected_device = FALSE;
vuln = FALSE;

if (
  device =~ " 42(0[35]|1[05]|20)($|[ \n\r])" || # 4200 series
  device =~ " 45(0[15]|1[05]|20)($|[ \n\r])" || # 4500 series
  device =~ " 53[12]0($|[ \n\r])" || # 5300 series
  device =~ " MSE 8420($|[ \n\r])" ||
  device =~ " MSE 8510($|[ \n\r])"
)
{
  found_affected_device = TRUE;
  if (
    cisco_gen_ver_compare(a:version, b:'4.0(1.18)') == 0 ||
    cisco_gen_ver_compare(a:version, b:'4.0(1.44)') == 0 ||
    cisco_gen_ver_compare(a:version, b:'4.0(1.49)') == 0 ||
    cisco_gen_ver_compare(a:version, b:'4.0(1.54)') == 0 ||
    cisco_gen_ver_compare(a:version, b:'4.1(1.51)') == 0 ||
    cisco_gen_ver_compare(a:version, b:'4.1(1.59)') == 0 ||
    cisco_gen_ver_compare(a:version, b:'4.2(1.43)') == 0 ||
    cisco_gen_ver_compare(a:version, b:'4.2(1.46)') == 0 ||
    cisco_gen_ver_compare(a:version, b:'4.2(1.50)') == 0 ||
    cisco_gen_ver_compare(a:version, b:'4.3(1.68)') == 0 ||
    cisco_gen_ver_compare(a:version, b:'4.3(2.18)') == 0 ||
    cisco_gen_ver_compare(a:version, b:'4.3(2.30)') == 0 ||
    cisco_gen_ver_compare(a:version, b:'4.3(2.32)') == 0 ||
    cisco_gen_ver_compare(a:version, b:'4.4(3.42)') == 0 ||
    cisco_gen_ver_compare(a:version, b:'4.4(3.49)') == 0 ||
    cisco_gen_ver_compare(a:version, b:'4.4(3.54)') == 0 ||
    cisco_gen_ver_compare(a:version, b:'4.4(3.57)') == 0 ||
    cisco_gen_ver_compare(a:version, b:'4.4(3.67)') == 0 ||
    cisco_gen_ver_compare(a:version, b:'4.5(1.45)') == 0
  ) vuln = TRUE;
}

if (!found_affected_device) exit(0, "The remote TelePresence device is not affected.");

if (vuln) security_warning(0);
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco TelePresence", version);
