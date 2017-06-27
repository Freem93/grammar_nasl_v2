#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200812-13.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(35101);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2008-2237", "CVE-2008-2238", "CVE-2008-4937");
  script_xref(name:"GLSA", value:"200812-13");

  script_name(english:"GLSA-200812-13 : OpenOffice.org: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200812-13
(OpenOffice.org: Multiple vulnerabilities)

    Two heap-based buffer overflows when processing WMF files
    (CVE-2008-2237) and EMF files (CVE-2008-2238) were discovered. Dmitry
    E. Oboukhov also reported an insecure temporary file usage within the
    senddoc script (CVE-2008-4937).
  
Impact :

    A remote attacker could entice a user to open a specially crafted
    document, resulting in the remote execution of arbitrary code. A local
    attacker could perform symlink attacks to overwrite arbitrary files on
    the system. Both cases happen with the privileges of the user running
    the application.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200812-13"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All OpenOffice.org users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-office/openoffice-3.0.0'
    All OpenOffice.org binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-office/openoffice-bin-3.0.0'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(59, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openoffice-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-office/openoffice-bin", unaffected:make_list("ge 3.0.0"), vulnerable:make_list("lt 3.0.0"))) flag++;
if (qpkg_check(package:"app-office/openoffice", unaffected:make_list("ge 3.0.0"), vulnerable:make_list("lt 3.0.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenOffice.org");
}
