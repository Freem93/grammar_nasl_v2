#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200410-17.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(15526);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 13:34:23 $");

  script_cve_id("CVE-2004-0752");
  script_osvdb_id(9804);
  script_xref(name:"GLSA", value:"200410-17");

  script_name(english:"GLSA-200410-17 : OpenOffice.org: Temporary files disclosure");
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
"The remote host is affected by the vulnerability described in GLSA-200410-17
(OpenOffice.org: Temporary files disclosure)

    On start-up, OpenOffice.org 1.1.2 creates a temporary directory with
    insecure permissions. When a document is saved, a compressed copy of it can
    be found in that directory.
  
Impact :

    A malicious local user could obtain the temporary files and thus read
    documents belonging to other users.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openoffice.org/issues/show_bug.cgi?id=33357"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200410-17"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All affected OpenOffice.org users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=app-office/openoffice-1.1.3'
    # emerge '>=app-office/openoffice-1.1.3'
    All affected OpenOffice.org binary users should upgrade to the latest
    version:
    # emerge sync
    # emerge -pv '>=app-office/openoffice-bin-1.1.3'
    # emerge '>=app-office/openoffice-bin-1.1.3'
    All affected OpenOffice.org Ximian users should upgrade to the latest
    version:
    # emerge sync
    # emerge -pv '>=app-office/openoffice-ximian-1.3.4'
    # emerge '>=app-office/openoffice-1.3.4'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openoffice-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openoffice-ximian");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/10");
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

if (qpkg_check(package:"app-office/openoffice-ximian", unaffected:make_list("lt 1.1.60", "ge 1.3.4"), vulnerable:make_list("eq 1.1.60", "eq 1.1.61"))) flag++;
if (qpkg_check(package:"app-office/openoffice-bin", unaffected:make_list("lt 1.1.2", "ge 1.1.3"), vulnerable:make_list("eq 1.1.2"))) flag++;
if (qpkg_check(package:"app-office/openoffice", unaffected:make_list("lt 1.1.2", "ge 1.1.3"), vulnerable:make_list("eq 1.1.2"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:qpkg_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenOffice.org");
}
