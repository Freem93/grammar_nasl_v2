#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K16716.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(91202);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/03/15 20:36:15 $");

  script_cve_id("CVE-2013-1740", "CVE-2014-1490", "CVE-2014-1491", "CVE-2014-1492", "CVE-2014-1544", "CVE-2014-1545");
  script_bugtraq_id(64944, 65332, 65335, 66356, 67975, 68816);
  script_osvdb_id(102170, 102876, 102877, 104708, 107912, 109430);

  script_name(english:"F5 Networks BIG-IP : Multiple Mozilla NSS vulnerabilities (K16716)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2013-1740 The ssl_Do1stHandshake function in sslsecur.c in libssl
in Mozilla Network Security Services (NSS) before 3.15.4, when the TLS
False Start feature is enabled, allows man-in-the-middle attackers to
spoof SSL servers by using an arbitrary X.509 certificate during
certain handshake traffic.

CVE-2014-1490 Race condition in libssl in Mozilla Network Security
Services (NSS) before 3.15.4, as used in Mozilla Firefox before 27.0,
Firefox ESR 24.x before 24.3, Thunderbird before 24.3, SeaMonkey
before 2.24, and other products, allows remote attackers to cause a
denial of service (use-after-free) or possibly have unspecified other
impact via vectors involving a resumption handshake that triggers
incorrect replacement of a session ticket.

CVE-2014-1491 Mozilla Network Security Services (NSS) before 3.15.4,
as used in Mozilla Firefox before 27.0, Firefox ESR 24.x before 24.3,
Thunderbird before 24.3, SeaMonkey before 2.24, and other products,
does not properly restrict public values in Diffie-Hellman key
exchanges, which makes it easier for remote attackers to bypass
cryptographic protection mechanisms in ticket handling by leveraging
use of a certain value.

CVE-2014-1492 The cert_TestHostName function in lib/certdb/certdb.c in
the certificate-checking implementation in Mozilla Network Security
Services (NSS) before 3.16 accepts a wildcard character that is
iframeded in an internationalized domain name's U-label, which might
allow man-in-the-middle attackers to spoof SSL servers via a crafted
certificate.

CVE-2014-1544 Use-after-free vulnerability in the
CERT_DestroyCertificate function in libnss3.so in Mozilla Network
Security Services (NSS) 3.x, as used in Firefox before 31.0, Firefox
ESR 24.x before 24.7, and Thunderbird before 24.7, allows remote
attackers to execute arbitrary code via vectors that trigger certain
improper removal of an NSSCertificate structure from a trust domain.

CVE-2014-1545 Mozilla Netscape Portable Runtime (NSPR) before 4.10.6
allows remote attackers to execute arbitrary code or cause a denial of
service (out-of-bounds write) via vectors involving the sprintf and
console functions."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/#/article/K16716"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K16716."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"F5 Networks Local Security Checks");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version", "Settings/ParanoidReport");

  exit(0);
}


include("f5_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
version = get_kb_item("Host/BIG-IP/version");
if ( ! version ) audit(AUDIT_OS_NOT, "F5 Networks BIG-IP");
if ( isnull(get_kb_item("Host/BIG-IP/hotfix")) ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/hotfix");
if ( ! get_kb_item("Host/BIG-IP/modules") ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/modules");

sol = "K16716";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("11.3.0-11.6.0");
vmatrix["AFM"]["unaffected"] = make_list("12.0.0","11.6.1");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("11.4.0-11.6.0");
vmatrix["AM"]["unaffected"] = make_list("12.0.0","11.6.1");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("11.0.0-11.6.0","10.1.0-10.2.4");
vmatrix["APM"]["unaffected"] = make_list("12.0.0","11.6.1");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("11.0.0-11.6.0","10.1.0-10.2.4");
vmatrix["ASM"]["unaffected"] = make_list("12.0.0","11.6.1");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("11.0.0-11.6.0");
vmatrix["AVR"]["unaffected"] = make_list("12.0.0","11.6.1");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("11.0.0-11.6.0","10.1.0-10.2.4");
vmatrix["GTM"]["unaffected"] = make_list("11.6.1");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("11.0.0-11.6.0","10.1.0-10.2.4");
vmatrix["LC"]["unaffected"] = make_list("12.0.0","11.6.1");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("11.0.0-11.6.0","10.1.0-10.2.4");
vmatrix["LTM"]["unaffected"] = make_list("12.0.0","11.6.1");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("11.3.0-11.6.0");
vmatrix["PEM"]["unaffected"] = make_list("12.0.0","11.6.1");


if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  if (report_verbosity > 0) security_hole(port:0, extra:bigip_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = bigip_get_tested_modules();
  audit_extra = "For BIG-IP module(s) " + tested + ",";
  if (tested) audit(AUDIT_INST_VER_NOT_VULN, audit_extra, version);
  else audit(AUDIT_HOST_NOT, "running any of the affected modules");
}
