#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200710-31.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(27593);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 14:04:24 $");

  script_cve_id("CVE-2007-5540", "CVE-2007-5541");
  script_osvdb_id(38126, 38127, 38128);
  script_xref(name:"GLSA", value:"200710-31");

  script_name(english:"GLSA-200710-31 : Opera: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200710-31
(Opera: Multiple vulnerabilities)

    Michael A. Puls II discovered an unspecified flaw when launching
    external email or newsgroup clients (CVE-2007-5541). David Bloom
    discovered that when displaying frames from different websites, the
    same-origin policy is not correctly enforced (CVE-2007-5540).
  
Impact :

    An attacker could potentially exploit the first vulnerability to
    execute arbitrary code with the privileges of the user running Opera by
    enticing a user to visit a specially crafted URL. Note that this
    vulnerability requires an external e-mail or newsgroup client
    configured in Opera to be exploitable. The second vulnerability allows
    an attacker to execute arbitrary script code in a user's browser
    session in context of other sites or the theft of browser credentials.
  
Workaround :

    There is no known workaround at this time for all these
    vulnerabilities."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200710-31"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Opera users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/opera-9.24'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/31");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-client/opera", unaffected:make_list("ge 9.24"), vulnerable:make_list("lt 9.24"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Opera");
}
