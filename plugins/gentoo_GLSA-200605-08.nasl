#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200605-08.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(21350);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:49:35 $");

  script_cve_id("CVE-2006-0996", "CVE-2006-1490", "CVE-2006-1990", "CVE-2006-1991");
  script_osvdb_id(24248, 24484, 24944, 24946);
  script_xref(name:"GLSA", value:"200605-08");

  script_name(english:"GLSA-200605-08 : PHP: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200605-08
(PHP: Multiple vulnerabilities)

    Several vulnerabilities were discovered on PHP4 and PHP5 by Infigo,
    Tonu Samuel and Maksymilian Arciemowicz. These included a buffer
    overflow in the wordwrap() function, restriction bypasses in the copy()
    and tempname() functions, a cross-site scripting issue in the phpinfo()
    function, a potential crash in the substr_compare() function and a
    memory leak in the non-binary-safe html_entity_decode() function.
  
Impact :

    Remote attackers might be able to exploit these issues in PHP
    applications making use of the affected functions, potentially
    resulting in the execution of arbitrary code, Denial of Service,
    execution of scripted contents in the context of the affected site,
    security bypass or information leak.
  
Workaround :

    There is no known workaround at this point."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200605-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All PHP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-lang/php"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (ourarch !~ "^(alpha|amd64|ia64|ppc64)$") audit(AUDIT_ARCH_NOT, "alpha|amd64|ia64|ppc64", ourarch);

flag = 0;

if (qpkg_check(package:"dev-lang/php", arch:"alpha amd64 ia64 ppc64", unaffected:make_list("ge 5.1.4-r4", "rge 4.4.2-r6", "rge 4.4.3-r1", "rge 4.4.4-r4", "rge 4.4.6", "ge 4.4.7"), vulnerable:make_list("lt 5.1.4-r4"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PHP");
}
