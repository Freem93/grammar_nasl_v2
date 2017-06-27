#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200512-03.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(20312);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/07/10 14:11:55 $");

  script_cve_id("CVE-2005-3665", "CVE-2005-4079");
  script_osvdb_id(21486, 21487, 21508);
  script_xref(name:"GLSA", value:"200512-03");

  script_name(english:"GLSA-200512-03 : phpMyAdmin: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200512-03
(phpMyAdmin: Multiple vulnerabilities)

    Stefan Esser from Hardened-PHP reported about multiple
    vulnerabilties found in phpMyAdmin. The $GLOBALS variable allows
    modifying the global variable import_blacklist to open phpMyAdmin to
    local and remote file inclusion, depending on your PHP version
    (CVE-2005-4079, PMASA-2005-9). Furthermore, it is also possible to
    conduct an XSS attack via the $HTTP_HOST variable and a local and
    remote file inclusion because the contents of the variable are under
    total control of the attacker (CVE-2005-3665, PMASA-2005-8).
  
Impact :

    A remote attacker may exploit these vulnerabilities by sending
    malicious requests, causing the execution of arbitrary code with the
    rights of the user running the web server. The cross-site scripting
    issues allow a remote attacker to inject and execute malicious script
    code or to steal cookie-based authentication credentials, potentially
    allowing unauthorized access to phpMyAdmin.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2005-8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2005-9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.hardened-php.net/advisory_252005.110.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200512-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All phpMyAdmin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-db/phpmyadmin-2.7.0_p1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:phpmyadmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/12/15");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-db/phpmyadmin", unaffected:make_list("ge 2.7.0_p1"), vulnerable:make_list("lt 2.7.0_p1"))) flag++;

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
