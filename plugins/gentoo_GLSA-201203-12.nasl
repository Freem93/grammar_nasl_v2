#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201203-12.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(58222);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/05/16 13:53:26 $");

  script_cve_id("CVE-2011-4108", "CVE-2011-4109", "CVE-2011-4576", "CVE-2011-4577", "CVE-2011-4619", "CVE-2012-0027", "CVE-2012-0050");
  script_bugtraq_id(51281, 51563);
  script_osvdb_id(78186, 78187, 78188, 78189, 78190, 78191, 78320);
  script_xref(name:"GLSA", value:"201203-12");

  script_name(english:"GLSA-201203-12 : OpenSSL: Multiple vulnerabilities");
  script_summary(english:"Checks for updated package(s) in /var/db/pkg");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Gentoo host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is affected by the vulnerability described in GLSA-201203-12
(OpenSSL: Multiple vulnerabilities)

    Multiple vulnerabilities have been found in OpenSSL:
      Timing differences for decryption are exposed by CBC mode encryption
        in OpenSSL&rsquo;s implementation of DTLS (CVE-2011-4108).
      A policy check failure can result in a double-free error when
        X509_V_FLAG_POLICY_CHECK is set (CVE-2011-4109).
      Clients and servers using SSL 3.0 handshakes do not clear the block
        cipher padding, allowing a record to contain up to 15 bytes of
        uninitialized memory, which could include sensitive information
        (CVE-2011-4576).
      Assertion errors can occur during the handling of malformed X.509
        certificates when OpenSSL is built with RFC 3779 support
        (CVE-2011-4577).
      A resource management error can occur when OpenSSL&rsquo;s server gated
        cryptography (SGC) does not properly handle handshake restarts
        (CVE-2011-4619).
      Invalid parameters in the GOST block cipher are not properly handled
        by the GOST ENGINE(CVE-2012-0027).
      An incorrect fix for CVE-2011-4108 creates an unspecified
        vulnerability for DTLS applications using OpenSSL (CVE-2012-0050).
  
Impact :

    A remote attacker may be able to cause a Denial of Service or obtain
      sensitive information, including plaintext passwords.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201203-12"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All OpenSSL users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-libs/openssl-1.0.0g'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (qpkg_check(package:"dev-libs/openssl", unaffected:make_list("ge 1.0.0g", "rge 0.9.8t", "rge 0.9.8u", "rge 0.9.8v", "rge 0.9.8w", "rge 0.9.8x", "rge 0.9.8y", "rge 0.9.8z_p1", "rge 0.9.8z_p2", "rge 0.9.8z_p3", "rge 0.9.8z_p4", "rge 0.9.8z_p5", "rge 0.9.8z_p6", "rge 0.9.8z_p7", "rge 0.9.8z_p8", "rge 0.9.8z_p9", "rge 0.9.8z_p10", "rge 0.9.8z_p11", "rge 0.9.8z_p12", "rge 0.9.8z_p13", "rge 0.9.8z_p14", "rge 0.9.8z_p15"), vulnerable:make_list("lt 1.0.0g"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:qpkg_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenSSL");
}
