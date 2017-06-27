#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200404-16.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14481);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/04/13 13:34:21 $");

  script_xref(name:"GLSA", value:"200404-16");

  script_name(english:"GLSA-200404-16 : Multiple new security vulnerabilities in monit");
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
"The remote host is affected by the vulnerability described in GLSA-200404-16
(Multiple new security vulnerabilities in monit)

    Monit has several vulnerabilities in its HTTP interface : a buffer overflow
    vulnerability in the authentication handling code and a off-by-one error in
    the POST method handling code.
  
Impact :

    An attacker may exploit the off-by-one error to crash the Monit daemon and
    create a denial of service condition, or cause a buffer overflow that would
    allow arbitrary code to be executed with root privileges.
  
Workaround :

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of the affected package."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.tildeslash.com/monit/secadv_20040305.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200404-16"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Monit users should upgrade to version 4.2.1 or later:
    # emerge sync
    # emerge -pv '>=app-admin/monit-4.2.1'
    # emerge '>=app-admin/monit-4.2.1'"
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:monit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
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

if (qpkg_check(package:"app-admin/monit", unaffected:make_list("ge 4.2.1"), vulnerable:make_list("le 4.2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "app-admin/monit");
}
