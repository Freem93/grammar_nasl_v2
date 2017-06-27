#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200706-07.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(25562);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:56:53 $");

  script_cve_id("CVE-2007-1575", "CVE-2007-1576", "CVE-2007-1638", "CVE-2007-1639");
  script_osvdb_id(34061, 34062, 34063, 34064, 34065, 34066, 34067, 34068, 34069, 35162, 35163);
  script_xref(name:"GLSA", value:"200706-07");

  script_name(english:"GLSA-200706-07 : PHProjekt: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200706-07
(PHProjekt: Multiple vulnerabilities)

    Alexios Fakos from n.runs AG has discovered multiple vulnerabilities in
    PHProjekt, including the execution of arbitrary SQL commands using
    unknown vectors (CVE-2007-1575), the execution of arbitrary PHP code
    using an unrestricted file upload (CVE-2007-1639), cross-site request
    forgeries using different modules (CVE-2007-1638), and a cross-site
    scripting attack using unkown vectors (CVE-2007-1576).
  
Impact :

    An authenticated user could elevate their privileges by exploiting the
    vulnerabilities described above. Note that the magic_quotes_gpc PHP
    configuration setting must be set to 'off' to exploit these
    vulnerabilities.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200706-07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All PHProjekt users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/phprojekt-5.2.1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:phprojekt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/14");
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

if (qpkg_check(package:"www-apps/phprojekt", unaffected:make_list("ge 5.2.1"), vulnerable:make_list("lt 5.2.1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PHProjekt");
}
