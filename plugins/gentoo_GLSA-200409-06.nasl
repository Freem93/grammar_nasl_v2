#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200409-06.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14653);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_cve_id("CVE-2004-1467");
  script_osvdb_id(9134, 9135, 9136, 9137, 9138);
  script_xref(name:"GLSA", value:"200409-06");

  script_name(english:"GLSA-200409-06 : eGroupWare: Multiple XSS vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200409-06
(eGroupWare: Multiple XSS vulnerabilities)

    Joxean Koret recently discovered multiple cross site scripting
    vulnerabilities in various modules for the eGroupWare suite. This
    includes the calendar, address book, messenger and ticket modules.
  
Impact :

    These vulnerabilities give an attacker the ability to inject and
    execute malicious script code, potentially compromising the victim's
    browser.
  
Workaround :

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of eGroupWare."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://sourceforge.net/forum/forum.php?forum_id=401807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/372603/2004-08-21/2004-08-27/0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200409-06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All eGroupWare users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=www-apps/egroupware-1.0.00.004'
    # emerge '>=www-apps/egroupware-1.0.00.004'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:egroupware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/21");
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

if (qpkg_check(package:"www-apps/egroupware", unaffected:make_list("ge 1.0.00.004"), vulnerable:make_list("le 1.0.00.003"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "eGroupWare");
}
