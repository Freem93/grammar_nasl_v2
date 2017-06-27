#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201603-15.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(90053);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/10/10 14:25:16 $");

  script_cve_id("CVE-2016-0702", "CVE-2016-0703", "CVE-2016-0704", "CVE-2016-0705", "CVE-2016-0797", "CVE-2016-0798", "CVE-2016-0799", "CVE-2016-0800");
  script_xref(name:"GLSA", value:"201603-15");

  script_name(english:"GLSA-201603-15 : OpenSSL: Multiple vulnerabilities (DROWN)");
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
"The remote host is affected by the vulnerability described in GLSA-201603-15
(OpenSSL: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in OpenSSL, the worst
      being a cross-protocol attack called DROWN that could lead to the
      decryption of TLS sessions. Please review the CVE identifiers referenced
      below for details.
  
Impact :

    A remote attacker could decrypt TLS sessions by using a server
      supporting SSLv2 and EXPORT cipher suites as a
      Bleichenbacher RSA padding oracle, cause a Denial of Service condition,
      obtain sensitive information from memory and (in rare circumstances)
      recover RSA keys.
  
Workaround :

    A workaround for DROWN is disabling the SSLv2 protocol on all SSL/TLS
      servers."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201603-15"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All OpenSSL users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-libs/openssl-1.0.2g-r2'
    Please note that beginning with OpenSSL 1.0.2, in order to mitigate the
      DROWN attack, the OpenSSL project disables SSLv2 by default at
      build-time. As this change would cause severe issues with some Gentoo
      packages that depend on OpenSSL, Gentoo still ships OpenSSL with SSLv2
      enabled at build-time. Note that this does not mean that you are still
      vulnerable to DROWN because the OpenSSL project has taken further
      precautions and applications would need to explicitly request SSLv2. We
      are working on a migration path to phase out SSLv2 that ensures that no
      user-facing issues occur. Please reference bug 576128 for further details
      on how this decision was made."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/20");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-libs/openssl", unaffected:make_list("ge 1.0.2g-r2"), vulnerable:make_list("lt 1.0.2g-r2"))) flag++;

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
