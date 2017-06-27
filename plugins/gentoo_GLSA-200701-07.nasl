#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200701-07.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(24205);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:56:52 $");

  script_cve_id("CVE-2006-5870");
  script_osvdb_id(32610, 32611);
  script_xref(name:"GLSA", value:"200701-07");

  script_name(english:"GLSA-200701-07 : OpenOffice.org: EMF/WMF file handling vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200701-07
(OpenOffice.org: EMF/WMF file handling vulnerabilities)

    John Heasman of NGSSoftware has discovered integer overflows in the
    EMR_POLYPOLYGON and EMR_POLYPOLYGON16 processing and an error within
    the handling of META_ESCAPE records.
  
Impact :

    An attacker could exploit these vulnerabilities to cause heap overflows
    and potentially execute arbitrary code with the privileges of the user
    running OpenOffice.org by enticing the user to open a document
    containing a malicious WMF/EMF file.
  
Workaround :

    There is no known workaround known at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200701-07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All OpenOffice.org binary users should update to version 2.1.0 or
    later:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-office/openoffice-bin-2.1.0'
    All OpenOffice.org users should update to version 2.0.4 or later:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-office/openoffice-2.0.4'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openoffice-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/17");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/04");
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

if (qpkg_check(package:"app-office/openoffice-bin", unaffected:make_list("ge 2.1.0"), vulnerable:make_list("lt 2.1.0"))) flag++;
if (qpkg_check(package:"app-office/openoffice", unaffected:make_list("ge 2.0.4"), vulnerable:make_list("lt 2.0.4"))) flag++;

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
