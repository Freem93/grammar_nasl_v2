#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201009-03.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(49124);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/04/13 14:19:43 $");

  script_cve_id("CVE-2010-1646", "CVE-2010-2956");
  script_osvdb_id(65083, 67842);
  script_xref(name:"GLSA", value:"201009-03");

  script_name(english:"GLSA-201009-03 : sudo: Privilege Escalation");
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
"The remote host is affected by the vulnerability described in GLSA-201009-03
(sudo: Privilege Escalation)

    Multiple vulnerabilities have been reported in sudo:
    Evan
    Broder and Anders Kaseorg of Ksplice, Inc. reported that the sudo
    'secure path' feature does not properly handle multiple PATH variables
    (CVE-2010-1646).
    Markus Wuethrich of Swiss Post reported that
    sudo fails to restrict access when using Runas groups and the group
    (-g) command line option (CVE-2010-2956).
  
Impact :

    A local attacker could exploit these vulnerabilities to gain the
    ability to run certain commands with the privileges of other users,
    including root, depending on the configuration.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201009-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All sudo users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-admin/sudo-1.7.4_p3-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sudo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-admin/sudo", unaffected:make_list("ge 1.7.4_p3-r1"), vulnerable:make_list("lt 1.7.4_p3-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sudo");
}
