#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201503-11.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(82010);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/22 14:14:59 $");

  script_cve_id("CVE-2015-0204", "CVE-2015-0207", "CVE-2015-0208", "CVE-2015-0209", "CVE-2015-0285", "CVE-2015-0287", "CVE-2015-0288", "CVE-2015-0289", "CVE-2015-0290", "CVE-2015-0291", "CVE-2015-0292", "CVE-2015-0293", "CVE-2015-1787");
  script_xref(name:"GLSA", value:"201503-11");

  script_name(english:"GLSA-201503-11 : OpenSSL: Multiple vulnerabilities (FREAK)");
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
"The remote host is affected by the vulnerability described in GLSA-201503-11
(OpenSSL: Multiple vulnerabilities)

    Multiple vulnerabilities have been found in OpenSSL. Please review the
      CVE identifiers and the upstream advisory referenced below for details:
      RSA silently downgrades to EXPORT_RSA [Client] (Reclassified)
        (CVE-2015-0204)
      Segmentation fault in ASN1_TYPE_cmp (CVE-2015-0286)
      ASN.1 structure reuse memory corruption (CVE-2015-0287)
      X509_to_X509_REQ NULL pointer deref (CVE-2015-0288)
      PKCS7 NULL pointer dereferences (CVE-2015-0289)
      Base64 decode (CVE-2015-0292)
      DoS via reachable assert in SSLv2 servers (CVE-2015-0293)
      Use After Free following d2i_ECPrivatekey error (CVE-2015-0209)
    The following issues affect OpenSSL 1.0.2 only which is not part of the
      supported Gentoo stable tree:
      OpenSSL 1.0.2 ClientHello sigalgs DoS (CVE-2015-0291)
      Multiblock corrupted pointer (CVE-2015-0290)
      Segmentation fault in DTLSv1_listen (CVE-2015-0207)
      Segmentation fault for invalid PSS parameters (CVE-2015-0208)
      Empty CKE with client auth and DHE (CVE-2015-1787)
      Handshake with unseeded PRNG (CVE-2015-0285)
  
Impact :

    A remote attacker can utilize multiple vectors to cause Denial of
      Service or Information Disclosure.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://openssl.org/news/secadv/20150319.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201503-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All OpenSSL 1.0.1 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-libs/openssl-1.0.1l-r1'
    All OpenSSL 0.9.8 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-libs/openssl-0.9.8z_p5-r1'
    Packages which depend on the OpenSSL library need to be restarted for
      the upgrade to take effect. Some packages may need to be recompiled.
      Tools such as revdep-rebuild may assist in identifying some of these
      packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/19");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-libs/openssl", unaffected:make_list("ge 1.0.1l-r1", "rge 0.9.8z_p5", "rge 0.9.8z_p6", "rge 0.9.8z_p7", "rge 0.9.8z_p8", "rge 0.9.8z_p9", "rge 0.9.8z_p10", "rge 0.9.8z_p11", "rge 0.9.8z_p12", "rge 0.9.8z_p13", "rge 0.9.8z_p14", "rge 0.9.8z_p15"), vulnerable:make_list("lt 1.0.1l-r1"))) flag++;

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
