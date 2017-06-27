#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200409-15.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14705);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_cve_id("CVE-2004-0559", "CVE-2004-1468");
  script_osvdb_id(9775);
  script_xref(name:"GLSA", value:"200409-15");

  script_name(english:"GLSA-200409-15 : Webmin, Usermin: Multiple vulnerabilities in Usermin");
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
"The remote host is affected by the vulnerability described in GLSA-200409-15
(Webmin, Usermin: Multiple vulnerabilities in Usermin)

    There is an input validation bug in the webmail feature of Usermin.
    Additionally, the Webmin and Usermin installation scripts write to
    /tmp/.webmin without properly checking if it exists first.
  
Impact :

    The first vulnerability allows a remote attacker to inject arbitrary
    shell code in a specially crafted e-mail. This could lead to remote
    code execution with the privileges of the user running Webmin or
    Usermin.
    The second could allow local users who know Webmin or Usermin is going
    to be installed to have arbitrary files be overwritten by creating a
    symlink by the name /tmp/.webmin that points to some target file, e.g.
    /etc/passwd.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/advisories/12488/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.webmin.com/uchanges.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200409-15"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Usermin users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=app-admin/usermin-1.090'
    # emerge '>=app-admin/usermin-1.090'
    All Webmin users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=app-admin/webmin-1.160'
    # emerge '>=app-admin/webmin-1.160'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:usermin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:webmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/05");
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

if (qpkg_check(package:"app-admin/usermin", unaffected:make_list("ge 1.090"), vulnerable:make_list("lt 1.090"))) flag++;
if (qpkg_check(package:"app-admin/webmin", unaffected:make_list("ge 1.160"), vulnerable:make_list("lt 1.160"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Webmin / Usermin");
}
