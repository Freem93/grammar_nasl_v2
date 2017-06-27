#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201408-19.
#
# The advisory text is Copyright (C) 2001-2017 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(77467);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/02/17 15:06:27 $");

  script_cve_id("CVE-2006-4339", "CVE-2009-0200", "CVE-2009-0201", "CVE-2009-0217", "CVE-2009-2949", "CVE-2009-2950", "CVE-2009-3301", "CVE-2009-3302", "CVE-2010-0395", "CVE-2010-2935", "CVE-2010-2936", "CVE-2010-3450", "CVE-2010-3451", "CVE-2010-3452", "CVE-2010-3453", "CVE-2010-3454", "CVE-2010-3689", "CVE-2010-4253", "CVE-2010-4643", "CVE-2011-2713", "CVE-2012-0037", "CVE-2012-1149", "CVE-2012-2149", "CVE-2012-2334", "CVE-2012-2665", "CVE-2014-0247");
  script_bugtraq_id(35671, 36200, 38218, 40599, 42202, 46031, 49969, 52681, 53570, 54769, 68151);
  script_osvdb_id(28549, 65203, 70712, 70713, 70714, 70715, 81989);
  script_xref(name:"GLSA", value:"201408-19");

  script_name(english:"GLSA-201408-19 : OpenOffice, LibreOffice: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201408-19
(OpenOffice, LibreOffice: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in OpenOffice and
      Libreoffice. Please review the CVE identifiers referenced below for
      details.
  
Impact :

    A remote attacker could entice a user to open a specially crafted file
      using OpenOffice, possibly resulting in execution of arbitrary code with
      the privileges of the process, a Denial of Service condition, execution
      of arbitrary Python code, authentication bypass, or reading and writing
      of arbitrary files.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201408-19"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All OpenOffice (binary) users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=app-office/openoffice-bin-3.5.5.3'
    All LibreOffice users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-office/libreoffice-4.2.5.2'
    All LibreOffice (binary) users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=app-office/libreoffice-bin-4.2.5.2'
    We recommend that users unmerge OpenOffice:
      # emerge --unmerge 'app-office/openoffice'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(94, 119, 189, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libreoffice-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openoffice-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/01");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-office/libreoffice", unaffected:make_list("ge 4.2.5.2"), vulnerable:make_list("lt 4.2.5.2"))) flag++;
if (qpkg_check(package:"app-office/openoffice-bin", unaffected:make_list("ge 3.5.5.3"), vulnerable:make_list("lt 3.5.5.3"))) flag++;
if (qpkg_check(package:"app-office/libreoffice-bin", unaffected:make_list("ge 4.2.5.2"), vulnerable:make_list("lt 4.2.5.2"))) flag++;
if (qpkg_check(package:"app-office/openoffice", unaffected:make_list(), vulnerable:make_list("le 3.5.5.3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenOffice / LibreOffice");
}
