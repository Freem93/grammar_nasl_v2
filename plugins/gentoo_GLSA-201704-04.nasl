#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201704-04.
#
# The advisory text is Copyright (C) 2001-2017 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(99699);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/27 13:33:46 $");

  script_cve_id("CVE-2017-3058", "CVE-2017-3059", "CVE-2017-3060", "CVE-2017-3061", "CVE-2017-3062", "CVE-2017-3063", "CVE-2017-3064");
  script_xref(name:"GLSA", value:"201704-04");

  script_name(english:"GLSA-201704-04 : Adobe Flash Player: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201704-04
(Adobe Flash Player: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Adobe Flash Player.
      Please review the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could possibly execute arbitrary code with the
      privileges of the process or bypass security restrictions.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201704-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Adobe Flash users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-plugins/adobe-flash-25.0.0.148'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:adobe-flash");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-plugins/adobe-flash", unaffected:make_list("ge 25.0.0.148"), vulnerable:make_list("lt 25.0.0.148"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Adobe Flash Player");
}
