#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76128);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/04 18:02:13 $");

  script_cve_id("CVE-2014-0195", "CVE-2014-0224");
  script_bugtraq_id(67899, 67900);
  script_osvdb_id(107729, 107730);
  script_xref(name:"CERT", value:"978508");

  script_name(english:"Cisco Adaptive Security Appliances Multiple Vulnerabilities in OpenSSL");
  script_summary(english:"Checks Cisco ASA device version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco ASA device is running a software version known to be
affected by multiple OpenSSL related vulnerabilities :

  - A buffer overflow error exists related to invalid DTLS
    fragment handling that could lead to execution of
    arbitrary code. Note this issue only affects OpenSSL
    when used as a DTLS client or server. (CVE-2014-0195)

  - An unspecified error exists that could allow an
    attacker to cause usage of weak keying material
    leading to simplified man-in-the-middle attacks.
    (CVE-2014-0224)

Note that Nessus has not checked for the presence of workarounds that
may mitigate these vulnerabilities.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140605-openssl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5539aa9d");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"solution", value:"Apply the recommended vendor supplied software update or workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");


  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

asa = get_kb_item_or_exit('Host/Cisco/ASA');
version = extract_asa_version(asa);
if (isnull(version)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

vuln = FALSE;

if (
  version =~ "^8\.0(\.|\()" &&
  cisco_gen_ver_compare(a:version, b:"8.0(5)39") <= 0 &&
  cisco_gen_ver_compare(a:version, b:"8.0(2)") >= 0
) vuln = TRUE;

else if (
  version =~ "^8\.1(\.|\()" &&
  cisco_gen_ver_compare(a:version, b:"8.1(2)56") <= 0 &&
  cisco_gen_ver_compare(a:version, b:"8.1(1)") >= 0
) vuln = TRUE;

else if (
  version =~ "^8\.2(\.|\()" &&
  cisco_gen_ver_compare(a:version, b:"8.2(5)49") <= 0 &&
  cisco_gen_ver_compare(a:version, b:"8.2(1)") >= 0
) vuln = TRUE;

else if (
  version =~ "^8\.3(\.|\()" &&
  cisco_gen_ver_compare(a:version, b:"8.3(2)40") <= 0 &&
  cisco_gen_ver_compare(a:version, b:"8.3(1)") >= 0
) vuln = TRUE;

else if (
  version =~ "^8\.4(\.|\()" &&
  cisco_gen_ver_compare(a:version, b:"8.4(7)20") <= 0 &&
  cisco_gen_ver_compare(a:version, b:"8.4(1)") >= 0
) vuln = TRUE;

else if (
  version =~ "^8\.5(\.|\()" &&
  cisco_gen_ver_compare(a:version, b:"8.5(1)20") <= 0 &&
  cisco_gen_ver_compare(a:version, b:"8.5(1)") >= 0
) vuln = TRUE;

else if (
  version =~ "^8\.6(\.|\()" &&
  cisco_gen_ver_compare(a:version, b:"8.6(1)13") <= 0 &&
  cisco_gen_ver_compare(a:version, b:"8.6(1)") >= 0
) vuln = TRUE;

else if (
  version =~ "^8\.7(\.|\()" &&
  cisco_gen_ver_compare(a:version, b:"8.7(1)11") <= 0 &&
  cisco_gen_ver_compare(a:version, b:"8.7(1)") >= 0
) vuln = TRUE;

else if (
  version =~ "^9\.0(\.|\()" &&
  cisco_gen_ver_compare(a:version, b:"9.0(4)12") <= 0 &&
  cisco_gen_ver_compare(a:version, b:"9.0(1)") >= 0
) vuln = TRUE;

else if (
  version =~ "^9\.1(\.|\()" &&
  cisco_gen_ver_compare(a:version, b:"9.1(5)7") <= 0 &&
  cisco_gen_ver_compare(a:version, b:"9.1(1)") >= 0
) vuln = TRUE;

else if (
  cisco_gen_ver_compare(a:version, b:"9.2(1)") == 0
) vuln = TRUE;

if (vuln) security_warning(0);
else audit(AUDIT_INST_VER_NOT_VULN, 'ASA', version);

