#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200805-01.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(32149);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 14:04:25 $");

  script_cve_id("CVE-2008-1284");
  script_osvdb_id(42774);
  script_xref(name:"GLSA", value:"200805-01");

  script_name(english:"GLSA-200805-01 : Horde Application Framework: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200805-01
(Horde Application Framework: Multiple vulnerabilities)

    Multiple vulnerabilities have been reported in the Horde Application
    Framework:
    David Collins, Patrick Pelanne and the
    HostGator.com LLC support team discovered that the theme preference
    page does not sanitize POST variables for several options, allowing the
    insertion of NULL bytes and '..' sequences (CVE-2008-1284).
    An
    error exists in the Horde API allowing users to bypass security
    restrictions.
  
Impact :

    The first vulnerability can be exploited by a remote attacker to read
    arbitrary files and by remote authenticated attackers to execute
    arbitrary files. The second vulnerability can be exploited by
    authenticated remote attackers to perform restricted operations.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200805-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Horde Application Framework users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-3.1.7'
    All horde-groupware users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-groupware-1.0.5'
    All horde-kronolith users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-kronolith-2.1.7'
    All horde-mnemo users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-mnemo-2.1.2'
    All horde-nag users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-nag-2.1.4'
    All horde-webmail users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/horde-webmail-1.0.6'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_cwe_id(22);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:horde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:horde-groupware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:horde-kronolith");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:horde-mnemo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:horde-nag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:horde-webmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-apps/horde-webmail", unaffected:make_list("ge 1.0.6"), vulnerable:make_list("lt 1.0.6"))) flag++;
if (qpkg_check(package:"www-apps/horde", unaffected:make_list("ge 3.1.7"), vulnerable:make_list("lt 3.1.7"))) flag++;
if (qpkg_check(package:"www-apps/horde-kronolith", unaffected:make_list("ge 2.1.7"), vulnerable:make_list("lt 2.1.7"))) flag++;
if (qpkg_check(package:"www-apps/horde-groupware", unaffected:make_list("ge 1.0.5"), vulnerable:make_list("lt 1.0.5"))) flag++;
if (qpkg_check(package:"www-apps/horde-nag", unaffected:make_list("ge 2.1.4"), vulnerable:make_list("lt 2.1.4"))) flag++;
if (qpkg_check(package:"www-apps/horde-mnemo", unaffected:make_list("ge 2.1.2"), vulnerable:make_list("lt 2.1.2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Horde Application Framework");
}
