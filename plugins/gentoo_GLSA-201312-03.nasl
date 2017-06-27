#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201312-03.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(71169);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/12 14:46:29 $");

  script_cve_id("CVE-2006-7250", "CVE-2011-1945", "CVE-2012-0884", "CVE-2012-1165", "CVE-2012-2110", "CVE-2012-2333", "CVE-2012-2686", "CVE-2013-0166", "CVE-2013-0169");
  script_bugtraq_id(47888, 52181, 52428, 52764, 53158, 53476, 57755, 57778, 60268);
  script_osvdb_id(74632, 79650, 80039, 80040, 81223, 81810, 89848, 89865, 89866);
  script_xref(name:"GLSA", value:"201312-03");

  script_name(english:"GLSA-201312-03 : OpenSSL: Multiple Vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201312-03
(OpenSSL: Multiple Vulnerabilities)

    Multiple vulnerabilities have been discovered in OpenSSL. Please review
      the CVE identifiers referenced below for details.
  
Impact :

    Remote attackers can determine private keys, decrypt data, cause a
      Denial of Service or possibly have other unspecified impact.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201312-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All OpenSSL 1.0.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-libs/openssl-1.0.0j'
    All OpenSSL 0.9.8 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-libs/openssl-0.9.8y'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-libs/openssl", unaffected:make_list("ge 1.0.0j", "rge 0.9.8y", "rge 0.9.8z_p1", "rge 0.9.8z_p2", "rge 0.9.8z_p3", "rge 0.9.8z_p4", "rge 0.9.8z_p5", "rge 0.9.8z_p6", "rge 0.9.8z_p7", "rge 0.9.8z_p8", "rge 0.9.8z_p9", "rge 0.9.8z_p10", "rge 0.9.8z_p11", "rge 0.9.8z_p12", "rge 0.9.8z_p13", "rge 0.9.8z_p14", "rge 0.9.8z_p15"), vulnerable:make_list("lt 1.0.0j", "lt 0.9.8y"))) flag++;

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
