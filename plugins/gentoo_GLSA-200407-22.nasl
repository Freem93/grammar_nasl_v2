#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200407-22.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14555);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_cve_id("CVE-2004-2631", "CVE-2004-2632");
  script_osvdb_id(7314, 7315);
  script_xref(name:"GLSA", value:"200407-22");

  script_name(english:"GLSA-200407-22 : phpMyAdmin: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200407-22
(phpMyAdmin: Multiple vulnerabilities)

    Two serious vulnerabilities exist in phpMyAdmin. The first allows any
    user to alter the server configuration variables (including host, name,
    and password) by appending new settings to the array variables that
    hold the configuration in a GET statement. The second allows users to
    include arbitrary PHP code to be executed within an eval() statement in
    table name configuration settings. This second vulnerability is only
    exploitable if $cfg['LeftFrameLight'] is set to FALSE.
  
Impact :

    Authenticated users can alter configuration variables for their running
    copy of phpMyAdmin. The impact of this should be minimal. However, the
    second vulnerability would allow an authenticated user to execute
    arbitrary PHP code with the permissions of the webserver, potentially
    allowing a serious Denial of Service or further remote compromise.
  
Workaround :

    The second, more serious vulnerability is only exploitable if
    $cfg['LeftFrameLight'] is set to FALSE. In the default Gentoo
    installation, this is set to TRUE. There is no known workaround for the
    first."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/367486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200407-22"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All phpMyAdmin users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=dev-db/phpmyadmin-2.5.7_p1'
    # emerge '>=dev-db/phpmyadmin-2.5.7_p1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:phpmyadmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/28");
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

if (qpkg_check(package:"dev-db/phpmyadmin", unaffected:make_list("ge 2.5.7_p1"), vulnerable:make_list("le 2.5.7"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phpMyAdmin");
}
