#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200405-11.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14497);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:34:21 $");

  script_cve_id("CVE-2004-0411");
  script_xref(name:"GLSA", value:"200405-11");

  script_name(english:"GLSA-200405-11 : KDE URI Handler Vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200405-11
(KDE URI Handler Vulnerabilities)

    The telnet, rlogin, ssh and mailto URI handlers in KDE do not check for '-'
    at the beginning of the hostname passed. By crafting a malicious URI and
    entice an user to click on it, it is possible to pass an option to the
    programs started by the handlers (typically telnet, kmail...).
  
Impact :

    If the attacker controls the options passed to the URI handling programs,
    it becomes possible for example to overwrite arbitrary files (possibly
    leading to denial of service), to open kmail on an attacker-controlled
    remote display or with an alternate configuration file (possibly leading to
    control of the user account).
  
Workaround :

    There is no known workaround at this time. All users are advised to upgrade
    to a corrected version of kdelibs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200405-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Users of KDE 3.1 should upgrade to the corrected version of kdelibs:
    # emerge sync
    # emerge -pv '=kde-base/kdelibs-3.1.5-r1'
    # emerge '=kde-base/kdelibs-3.1.5-r1'
    Users of KDE 3.2 should upgrade to the latest available version of kdelibs:
    # emerge sync
    # emerge -pv '>=kde-base/kdelibs-3.2.2-r1'
    # emerge '>=kde-base/kdelibs-3.2.2-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/05/19");
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

if (qpkg_check(package:"kde-base/kdelibs", unaffected:make_list("ge 3.2.2-r1", "eq 3.1.5-r1"), vulnerable:make_list("le 3.2.2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kde-base/kdelibs");
}
