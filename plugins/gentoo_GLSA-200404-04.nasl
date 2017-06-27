#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200404-04.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14469);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/13 13:34:21 $");

  script_cve_id("CVE-2004-0107", "CVE-2004-0108");
  script_xref(name:"GLSA", value:"200404-04");

  script_name(english:"GLSA-200404-04 : Multiple vulnerabilities in sysstat");
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
"The remote host is affected by the vulnerability described in GLSA-200404-04
(Multiple vulnerabilities in sysstat)

    There are two vulnerabilities in the way sysstat handles symlinks:
    The isag utility, which displays sysstat data in a graphical format,
    creates a temporary file in an insecure manner.
    Two scripts in the sysstat package, post and trigger, create temporary
    files in an insecure manner.
  
Impact :

    Both vulnerabilities may allow an attacker to overwrite arbitrary files
    under the permissions of the user executing any of the affected
    utilities.
  
Workaround :

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of the affected package."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200404-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Systat users should upgrade to version 4.2 or later:
    # emerge sync
    # emerge -pv '>=app-admin/sysstat-5.0.2'
    # emerge '>=app-admin/sysstat-5.0.2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sysstat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list", "Host/Gentoo/arch");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);
ourarch = get_kb_item("Host/Gentoo/arch");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(amd64|ppc|sparc|x86)$") audit(AUDIT_ARCH_NOT, "amd64|ppc|sparc|x86", ourarch);

flag = 0;

if (qpkg_check(package:"app-admin/sysstat", arch:"x86 ppc sparc amd64", unaffected:make_list("ge 5.0.2"), vulnerable:make_list("lt 5.0.2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "app-admin/sysstat");
}
