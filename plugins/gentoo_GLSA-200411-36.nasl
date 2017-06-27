#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200411-36.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(15840);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/04/13 13:41:57 $");

  script_cve_id("CVE-2004-1055");
  script_osvdb_id(11930, 11931, 11932, 12238);
  script_xref(name:"GLSA", value:"200411-36");

  script_name(english:"GLSA-200411-36 : phpMyAdmin: Multiple XSS vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200411-36
(phpMyAdmin: Multiple XSS vulnerabilities)

    Cedric Cochin has discovered multiple cross-site scripting
    vulnerabilities in phpMyAdmin. These vulnerabilities can be exploited
    through the PmaAbsoluteUri parameter, the zero_rows parameter in
    read_dump.php, the confirm form, or an error message generated by the
    internal phpMyAdmin parser.
  
Impact :

    By sending a specially crafted request, an attacker can inject and
    execute malicious script code, potentially compromising the victim's
    browser.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2004-3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.netvigilance.com/html/advisory0005.htm"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200411-36"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All phpMyAdmin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-db/phpmyadmin-2.6.0_p3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:phpmyadmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-db/phpmyadmin", unaffected:make_list("ge 2.6.0_p3"), vulnerable:make_list("lt 2.6.0_p3"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:qpkg_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phpMyAdmin");
}