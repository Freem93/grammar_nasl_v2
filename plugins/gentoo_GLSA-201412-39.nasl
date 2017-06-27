#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201412-39.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(80244);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/06/08 17:19:25 $");

  script_cve_id("CVE-2013-6449", "CVE-2013-6450", "CVE-2014-3505", "CVE-2014-3506", "CVE-2014-3507", "CVE-2014-3509", "CVE-2014-3510", "CVE-2014-3511", "CVE-2014-3512", "CVE-2014-3513", "CVE-2014-3567", "CVE-2014-3568", "CVE-2014-5139");
  script_bugtraq_id(64530, 64618, 69076, 69077, 69078, 69079, 69081, 69082, 69083, 69084, 70584, 70585, 70586);
  script_xref(name:"GLSA", value:"201412-39");

  script_name(english:"GLSA-201412-39 : OpenSSL: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201412-39
(OpenSSL: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in OpenSSL. Please review
      the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker may be able to cause a Denial of Service condition,
      perform Man-in-the-Middle attacks, obtain sensitive information, or
      bypass security restrictions.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201412-39"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All OpenSSL 1.0.1 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-libs/openssl-1.0.1j'
    All OpenSSL 0.9.8 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-libs/openssl-0.9.8z_p2'
    Packages which depend on this library may need to be recompiled. Tools
      such as revdep-rebuild may assist in identifying these packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-libs/openssl", unaffected:make_list("ge 1.0.1j", "rge 0.9.8z_p2", "rge 0.9.8z_p3", "rge 0.9.8z_p4", "rge 0.9.8z_p5", "rge 0.9.8z_p6", "rge 0.9.8z_p7", "rge 0.9.8z_p8", "rge 0.9.8z_p9", "rge 0.9.8z_p10", "rge 0.9.8z_p11", "rge 0.9.8z_p12", "rge 0.9.8z_p13", "rge 0.9.8z_p14", "rge 0.9.8z_p15"), vulnerable:make_list("lt 1.0.1j"))) flag++;

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
