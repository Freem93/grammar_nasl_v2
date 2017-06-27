#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200504-13.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(18060);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/04/13 13:41:58 $");

  script_cve_id("CVE-2005-0941");
  script_osvdb_id(15491);
  script_xref(name:"GLSA", value:"200504-13");

  script_name(english:"GLSA-200504-13 : OpenOffice.Org: DOC document Heap Overflow");
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
"The remote host is affected by the vulnerability described in GLSA-200504-13
(OpenOffice.Org: DOC document Heap Overflow)

    AD-LAB has discovered a heap overflow in the 'StgCompObjStream::Load()'
    function when processing DOC documents.
  
Impact :

    An attacker could design a malicious DOC document containing a
    specially crafted header which, when processed by OpenOffice.Org, would
    result in the execution of arbitrary code with the rights of the user
    running the application.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openoffice.org/issues/show_bug.cgi?id=46388"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200504-13"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All OpenOffice.Org users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-office/openoffice-1.1.4-r1'
    All OpenOffice.Org binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-office/openoffice-bin-1.1.4-r1'
    All OpenOffice.Org Ximian users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose app-office/openoffice-ximian
    Note to PPC users: There is no stable OpenOffice.Org fixed version for
    the PPC architecture. Affected users should switch to the latest
    OpenOffice.Org Ximian version.
    Note to SPARC users: There is no stable OpenOffice.Org fixed version
    for the SPARC architecture. Affected users should switch to the latest
    OpenOffice.Org Ximian version."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openoffice-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openoffice-ximian");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/16");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/30");
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

if (qpkg_check(package:"app-office/openoffice-ximian", unaffected:make_list("ge 1.3.9-r1", "rge 1.3.6-r1", "rge 1.3.7-r1"), vulnerable:make_list("lt 1.3.9-r1"))) flag++;
if (qpkg_check(package:"app-office/openoffice-bin", unaffected:make_list("ge 1.1.4-r1"), vulnerable:make_list("lt 1.1.4-r1"))) flag++;
if (qpkg_check(package:"app-office/openoffice", unaffected:make_list("ge 1.1.4-r1"), vulnerable:make_list("lt 1.1.4-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenOffice.Org");
}
