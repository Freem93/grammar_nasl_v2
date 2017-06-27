#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200907-03.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(39614);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2009-0023", "CVE-2009-1955", "CVE-2009-1956");
  script_bugtraq_id(35221, 35251, 35253);
  script_osvdb_id(55057, 55058, 55059);
  script_xref(name:"GLSA", value:"200907-03");

  script_name(english:"GLSA-200907-03 : APR Utility Library: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200907-03
(APR Utility Library: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in the APR Utility
    Library:
    Matthew Palmer reported a heap-based buffer
    underflow while compiling search patterns in the
    apr_strmatch_precompile() function in strmatch/apr_strmatch.c
    (CVE-2009-0023).
    kcope reported that the expat XML parser in
    xml/apr_xml.c does not limit the amount of XML entities expanded
    recursively (CVE-2009-1955).
    C. Michael Pilato reported an
    off-by-one error in the apr_brigade_vprintf() function in
    buckets/apr_brigade.c (CVE-2009-1956).
  
Impact :

    A remote attacker could exploit these vulnerabilities to cause a Denial
    of Service (crash or memory exhaustion) via an Apache HTTP server
    running mod_dav or mod_dav_svn, or using several configuration files.
    Additionally, a remote attacker could disclose sensitive information or
    cause a Denial of Service by sending a specially crafted input. NOTE:
    Only big-endian architectures such as PPC and HPPA are affected by the
    latter flaw.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200907-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Apache Portable Runtime Utility Library users should upgrade to the
    latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-libs/apr-util-1.3.7'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:apr-util");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-libs/apr-util", unaffected:make_list("ge 1.3.7"), vulnerable:make_list("lt 1.3.7"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "APR Utility Library");
}
