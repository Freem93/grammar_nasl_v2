#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201311-14.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(71073);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/04/13 14:27:07 $");

  script_cve_id("CVE-2011-3193", "CVE-2013-0254");
  script_bugtraq_id(49723, 57772);
  script_osvdb_id(75652, 89908);
  script_xref(name:"GLSA", value:"201311-14");

  script_name(english:"GLSA-201311-14 : QtCore, QtGui: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201311-14
(QtCore, QtGui: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in QtCore and QtGui.
      Please review the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could entice a user to open a specially crafted file
      with an application linked against QtCore or QtGui, possibly resulting in
      execution of arbitrary code with the privileges of the process or a
      Denial of Service condition. Furthermore, a remote attacker might employ
      a specially crafted certificate to conduct man-in-the-middle attacks on
      SSL connections.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://labs.qt.nokia.com/2011/03/29/security-advisory-fraudulent-certificates/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a00ee90a"
  );
  # http://blog.qt.digia.com/2011/09/02/what-the-diginotar-security-breach-means-for-qt-users/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?283acef0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201311-14"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All QtCore users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-qt/qtcore-4.8.4-r2'
    All QtGui users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-qt/qtgui-4.8.4-r1'
    Packages which depend on this library may need to be recompiled. Tools
      such as revdep-rebuild may assist in identifying some of these packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:qtcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:qtgui");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-qt/qtgui", unaffected:make_list("ge 4.8.4-r1"), vulnerable:make_list("lt 4.8.4-r1"))) flag++;
if (qpkg_check(package:"dev-qt/qtcore", unaffected:make_list("ge 4.8.4-r2"), vulnerable:make_list("lt 4.8.4-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "QtCore / QtGui");
}
