#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200412-16.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(16003);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 13:41:57 $");

  script_cve_id("CVE-2004-1158", "CVE-2004-1171");
  script_osvdb_id(12248, 59838, 59846);
  script_xref(name:"GLSA", value:"200412-16");

  script_name(english:"GLSA-200412-16 : kdelibs, kdebase: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200412-16
(kdelibs, kdebase: Multiple vulnerabilities)

    Daniel Fabian discovered that the KDE core libraries contain a
    flaw allowing password disclosure by making a link to a remote file.
    When creating this link, the resulting URL contains authentication
    credentials used to access the remote file (CAN 2004-1171).
    The Konqueror webbrowser allows websites to load webpages into a window
    or tab currently used by another website (CAN-2004-1158).
  
Impact :

    A malicious user could have access to the authentication
    credentials of other users depending on the file permissions.
    A malicious website could use the window injection vulnerability to
    load content in a window apparently belonging to another website.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kde.org/info/security/advisory-20041209-1.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kde.org/info/security/advisory-20041213-1.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200412-16"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All kdelibs users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=kde-base/kdelibs-3.2.3-r4'
    All kdebase users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=kde-base/kdebase-3.2.3-r3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/19");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/29");
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

if (qpkg_check(package:"kde-base/kdebase", unaffected:make_list("rge 3.2.3-r3", "rge 3.3.1-r2"), vulnerable:make_list("lt 3.3.2-r1"))) flag++;
if (qpkg_check(package:"kde-base/kdelibs", unaffected:make_list("rge 3.2.3-r4", "rge 3.3.1-r2", "ge 3.3.2-r1"), vulnerable:make_list("lt 3.3.2-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdelibs / kdebase");
}
