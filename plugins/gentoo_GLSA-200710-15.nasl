#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200710-15.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(27050);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/10/08 14:57:50 $");

  script_cve_id("CVE-2007-4569");
  script_osvdb_id(41394);
  script_xref(name:"GLSA", value:"200710-15");

  script_name(english:"GLSA-200710-15 : KDM: Local privilege escalation");
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
"The remote host is affected by the vulnerability described in GLSA-200710-15
(KDM: Local privilege escalation)

    Kees Huijgen discovered an error when checking the credentials which
    can lead to a login without specifying a password. This only occurs
    when auto login is configured for at least one user and a password is
    required to shut down the machine.
  
Impact :

    A local attacker could gain root privileges and execute arbitrary
    commands by logging in as root without specifying root's password.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200710-15"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All KDM users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=kde-base/kdm-3.5.7-r2'
    All kdebase users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=kde-base/kdebase-3.5.7-r4'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:kdm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/15");
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

if (qpkg_check(package:"kde-base/kdebase", unaffected:make_list("ge 3.5.7-r4"), vulnerable:make_list("lt 3.5.7-r4"))) flag++;
if (qpkg_check(package:"kde-base/kdm", unaffected:make_list("ge 3.5.7-r2"), vulnerable:make_list("lt 3.5.7-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "KDM");
}
