#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201110-01.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(56425);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2009-3245", "CVE-2009-4355", "CVE-2010-0433", "CVE-2010-0740", "CVE-2010-0742", "CVE-2010-1633", "CVE-2010-2939", "CVE-2010-3864", "CVE-2010-4180", "CVE-2010-4252", "CVE-2011-0014", "CVE-2011-3207", "CVE-2011-3210");
  script_osvdb_id(61684, 62719, 62844, 63299, 65057, 65058, 66946, 69265, 69565, 69657, 70847, 75229, 75230);
  script_xref(name:"GLSA", value:"201110-01");

  script_name(english:"GLSA-201110-01 : OpenSSL: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201110-01
(OpenSSL: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in OpenSSL. Please review
      the CVE identifiers referenced below for details.
  
Impact :

    A context-dependent attacker could cause a Denial of Service, possibly
      execute arbitrary code, bypass intended key requirements, force the
      downgrade to unintended ciphers, bypass the need for knowledge of shared
      secrets and successfully authenticate, bypass CRL validation, or obtain
      sensitive information in applications that use OpenSSL.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201110-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All OpenSSL users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-libs/openssl-1.0.0e'
    NOTE: This is a legacy GLSA. Updates for all affected architectures are
      available since September 17, 2011. It is likely that your system is
      already no longer affected by most of these issues."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-libs/openssl", unaffected:make_list("ge 1.0.0e", "rge 0.9.8r", "rge 0.9.8s", "rge 0.9.8t", "rge 0.9.8u", "rge 0.9.8v", "rge 0.9.8w", "rge 0.9.8x", "rge 0.9.8y", "rge 0.9.8z_p1", "rge 0.9.8z_p2", "rge 0.9.8z_p3", "rge 0.9.8z_p4", "rge 0.9.8z_p5", "rge 0.9.8z_p6", "rge 0.9.8z_p7", "rge 0.9.8z_p8", "rge 0.9.8z_p9", "rge 0.9.8z_p10", "rge 0.9.8z_p11", "rge 0.9.8z_p12", "rge 0.9.8z_p13", "rge 0.9.8z_p14", "rge 0.9.8z_p15"), vulnerable:make_list("lt 1.0.0e"))) flag++;

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
