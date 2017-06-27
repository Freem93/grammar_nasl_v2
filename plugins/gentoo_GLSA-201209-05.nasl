#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201209-05.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(62286);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/04/13 14:19:45 $");

  script_cve_id("CVE-2011-2713", "CVE-2012-0037", "CVE-2012-1149", "CVE-2012-2665");
  script_bugtraq_id(49969, 52681, 53570, 54769);
  script_osvdb_id(76178, 80307, 81988, 84440, 84441, 84442);
  script_xref(name:"GLSA", value:"201209-05");

  script_name(english:"GLSA-201209-05 : LibreOffice: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201209-05
(LibreOffice: Multiple vulnerabilities)

    Multiple vulnerabilities have been found in LibreOffice:
      The Microsoft Word Document parser contains an out-of-bounds read
        error (CVE-2011-2713).
      The Raptor RDF parser contains an XML External Entity expansion error
        (CVE-2012-0037).
      The graphic loading parser contains an integer overflow error which
        could cause a heap-based buffer overflow (CVE-2012-1149).
      Multiple errors in the XML manifest handling code could cause a
        heap-based buffer overflow (CVE-2012-2665).
  
Impact :

    A remote attacker could entice a user to open a specially crafted
      document file using LibreOffice, possibly resulting in execution of
      arbitrary code with the privileges of the process or a Denial of Service
      condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201209-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All LibreOffice users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-office/libreoffice-3.5.5.3'
    All users of the LibreOffice binary package should upgrade to the latest
      version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=app-office/libreoffice-bin-3.5.5.3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libreoffice-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-office/libreoffice", unaffected:make_list("ge 3.5.5.3"), vulnerable:make_list("lt 3.5.5.3"))) flag++;
if (qpkg_check(package:"app-office/libreoffice-bin", unaffected:make_list("ge 3.5.5.3"), vulnerable:make_list("lt 3.5.5.3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "LibreOffice");
}
