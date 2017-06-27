#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200607-12.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(22120);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/04/13 13:49:35 $");

  script_cve_id("CVE-2006-2198", "CVE-2006-2199", "CVE-2006-3117");
  script_osvdb_id(26939, 26940, 26941, 26942, 26943, 26944, 26945);
  script_xref(name:"GLSA", value:"200607-12");

  script_name(english:"GLSA-200607-12 : OpenOffice.org: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200607-12
(OpenOffice.org: Multiple vulnerabilities)

    Internal security audits by OpenOffice.org have discovered three
    security vulnerabilities related to Java applets, macros and the XML
    file format parser.
    Specially crafted Java applets can
    break through the 'sandbox'.
    Specially crafted macros make it
    possible to inject BASIC code into documents which is executed when the
    document is loaded.
    Loading a malformed XML file can cause a
    buffer overflow.
  
Impact :

    An attacker might exploit these vulnerabilities to escape the Java
    sandbox, execute arbitrary code or BASIC code with the permissions of
    the user running OpenOffice.org.
  
Workaround :

    Disabling Java applets will protect against the vulnerability in the
    handling of Java applets. There are no workarounds for the macro and
    file format vulnerabilities."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openoffice.org/security/bulletin-20060629.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200607-12"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All OpenOffice.org users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-office/openoffice-2.0.3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openoffice-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-office/openoffice-bin", unaffected:make_list("ge 2.0.3"), vulnerable:make_list("lt 2.0.3"))) flag++;
if (qpkg_check(package:"app-office/openoffice", unaffected:make_list("ge 2.0.3"), vulnerable:make_list("lt 2.0.3"))) flag++;

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
