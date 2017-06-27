#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200405-04.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14490);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:34:21 $");

  script_cve_id("CVE-2004-0179");
  script_xref(name:"GLSA", value:"200405-04");

  script_name(english:"GLSA-200405-04 : OpenOffice.org vulnerability when using DAV servers");
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
"The remote host is affected by the vulnerability described in GLSA-200405-04
(OpenOffice.org vulnerability when using DAV servers)

    OpenOffice.org includes code from the Neon library in functions related to
    publication on WebDAV servers. This library is vulnerable to several format
    string attacks.
  
Impact :

    If you use the WebDAV publication and connect to a malicious WebDAV server,
    this server can exploit these vulnerabilities to execute arbitrary code
    with the rights of the user running OpenOffice.org.
  
Workaround :

    As a workaround, you should not use the WebDAV publication facilities."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200405-01.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200405-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"There is no Ximian OpenOffice.org binary version including the fix yet. All
    users of the openoffice-ximian-bin package making use of the WebDAV
    openoffice-ximian source-based package.
    openoffice users on the x86 architecture should:
    # emerge sync
    # emerge -pv '>=app-office/openoffice-1.1.1-r1'
    # emerge '>=app-office/openoffice-1.1.1-r1'
    openoffice users on the sparc architecture should:
    # emerge sync
    # emerge -pv '>=app-office/openoffice-1.1.0-r3'
    # emerge '>=app-office/openoffice-1.1.0-r3'
    openoffice users on the ppc architecture should:
    # emerge sync
    # emerge -pv '>=app-office/openoffice-1.0.3-r1'
    # emerge '>=app-office/openoffice-1.0.3-r1'
    openoffice-ximian users should:
    # emerge sync
    # emerge -pv '>=app-office/openoffice-ximian-1.1.51-r1'
    # emerge '>=app-office/openoffice-ximian-1.1.51-r1'
    openoffice-bin users should:
    # emerge sync
    # emerge -pv '>=app-office/openoffice-bin-1.1.2'
    # emerge '>=app-office/openoffice-bin-1.1.2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openoffice-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openoffice-ximian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openoffice-ximian-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/05/11");
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


flag = 0;

if (qpkg_check(package:"app-office/openoffice-ximian", unaffected:make_list("ge 1.1.51-r1"), vulnerable:make_list("le 1.1.51"))) flag++;
if (qpkg_check(package:"app-office/openoffice-ximian-bin", unaffected:make_list(), vulnerable:make_list("le 1.1.52"))) flag++;
if (qpkg_check(package:"app-office/openoffice-bin", unaffected:make_list("ge 1.1.2"), vulnerable:make_list("lt 1.1.2"))) flag++;
if (qpkg_check(package:"app-office/openoffice", arch:"sparc", unaffected:make_list("ge 1.1.0-r4"), vulnerable:make_list("le 1.1.0-r3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "app-office/openoffice-ximian / app-office/openoffice-ximian-bin / etc");
}
