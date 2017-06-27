#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201407-05.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(76864);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/12 14:46:29 $");

  script_cve_id("CVE-2010-5298", "CVE-2014-0195", "CVE-2014-0198", "CVE-2014-0221", "CVE-2014-0224", "CVE-2014-3470");
  script_bugtraq_id(66801, 67193, 67898, 67899, 67900, 67901);
  script_osvdb_id(105763, 106531, 107729, 107730, 107731, 107732);
  script_xref(name:"GLSA", value:"201407-05");

  script_name(english:"GLSA-201407-05 : OpenSSL: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201407-05
(OpenSSL: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in OpenSSL. Please review
      the OpenSSL Security Advisory [05 Jun 2014] and the CVE identifiers
      referenced below for details.
  
Impact :

    A remote attacker could send specially crafted DTLS fragments to an
      OpenSSL DTLS client or server to possibly execute arbitrary code with the
      privileges of the process using OpenSSL.
    Furthermore, an attacker could force the use of weak keying material in
      OpenSSL SSL/TLS clients and servers, inject data across sessions, or
      cause a Denial of Service via various vectors.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openssl.org/news/secadv/20140605.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201407-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All OpenSSL users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-libs/openssl-1.0.1h-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-libs/openssl", unaffected:make_list("ge 1.0.1h-r1", "rge 1.0.0m", "rge 0.9.8z_p1", "rge 0.9.8z_p2", "rge 0.9.8z_p3", "rge 0.9.8z_p4", "rge 0.9.8z_p5", "rge 0.9.8z_p6", "rge 0.9.8z_p7", "rge 0.9.8z_p8", "rge 0.9.8z_p9", "rge 0.9.8z_p10", "rge 0.9.8z_p11", "rge 0.9.8z_p12", "rge 0.9.8z_p13", "rge 0.9.8z_p14", "rge 0.9.8z_p15"), vulnerable:make_list("lt 1.0.1h-r1"))) flag++;

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
