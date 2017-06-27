#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201611-03.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(94594);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/03/06 15:01:21 $");

  script_cve_id("CVE-2015-4551", "CVE-2015-5212", "CVE-2015-5213", "CVE-2015-5214", "CVE-2016-4324");
  script_xref(name:"GLSA", value:"201611-03");

  script_name(english:"GLSA-201611-03 : LibreOffice, OpenOffice: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201611-03
(LibreOffice, OpenOffice: Multiple vulnerabilities)

    Multiple vulnerabilities have been found in both LibreOffice and
      OpenOffice.  Please review the referenced CVE&rsquo;s for specific
      information regarding each.
  
Impact :

    Remote attackers could obtain sensitive information, cause a Denial of
      Service condition, or execute arbitrary code.
  
Workaround :

    There is no known work around at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201611-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All LibreOffice users should upgrade their respective packages to the
      latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-office/libreoffice-5.1.4.2'
      # emerge --ask --oneshot --verbose
      '>=app-office/libreoffice-bin-debug-5.1.4.2'
    All OpenOffice users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-office/openoffice-bin-4.1.2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libreoffice-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openoffice-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-office/libreoffice", unaffected:make_list("ge 5.1.4.2"), vulnerable:make_list("lt 5.1.4.2"))) flag++;
if (qpkg_check(package:"app-office/openoffice-bin", unaffected:make_list("ge 4.1.2"), vulnerable:make_list("lt 4.1.2"))) flag++;
if (qpkg_check(package:"app-office/libreoffice-bin", unaffected:make_list("ge 5.1.4.2"), vulnerable:make_list("lt 5.1.4.2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "LibreOffice / OpenOffice");
}
