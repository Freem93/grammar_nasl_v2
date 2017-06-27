#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200512-02.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(20281);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:49:34 $");

  script_cve_id("CVE-2005-3912");
  script_osvdb_id(21222);
  script_xref(name:"GLSA", value:"200512-02");

  script_name(english:"GLSA-200512-02 : Webmin, Usermin: Format string vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200512-02
(Webmin, Usermin: Format string vulnerability)

    Jack Louis discovered that the Webmin and Usermin 'miniserv.pl'
    web server component is vulnerable to a Perl format string
    vulnerability. Login with the supplied username is logged via the Perl
    'syslog' facility in an unsafe manner.
  
Impact :

    A remote attacker can trigger this vulnerability via a specially
    crafted username containing format string data. This can be exploited
    to consume a large amount of CPU and memory resources on a vulnerable
    system, and possibly to execute arbitrary code of the attacker's choice
    with the permissions of the user running Webmin.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://www.dyadsecurity.com/webmin-0001.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e5db4928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200512-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Webmin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-admin/webmin-1.250'
    All Usermin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-admin/usermin-1.180'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:usermin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:webmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/12/08");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-admin/usermin", unaffected:make_list("ge 1.180"), vulnerable:make_list("lt 1.180"))) flag++;
if (qpkg_check(package:"app-admin/webmin", unaffected:make_list("ge 1.250"), vulnerable:make_list("lt 1.250"))) flag++;

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
