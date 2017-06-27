#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200511-08.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(20195);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:49:33 $");

  script_cve_id("CVE-2005-3054", "CVE-2005-3319", "CVE-2005-3388", "CVE-2005-3389", "CVE-2005-3390", "CVE-2005-3391", "CVE-2005-3392");
  script_osvdb_id(20406, 20407, 20408);
  script_xref(name:"GLSA", value:"200511-08");

  script_name(english:"GLSA-200511-08 : PHP: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200511-08
(PHP: Multiple vulnerabilities)

    Multiple vulnerabilities have been found and fixed in PHP:
    a possible $GLOBALS variable overwrite problem through file
    upload handling, extract() and import_request_variables()
    (CVE-2005-3390)
    a local Denial of Service through the use of
    the session.save_path option (CVE-2005-3319)
    an issue with
    trailing slashes in allowed basedirs (CVE-2005-3054)
    an issue
    with calling virtual() on Apache 2, allowing to bypass safe_mode and
    open_basedir restrictions (CVE-2005-3392)
    a problem when a
    request was terminated due to memory_limit constraints during certain
    parse_str() calls (CVE-2005-3389)
    The curl and gd modules
    allowed to bypass the safe mode open_basedir restrictions
    (CVE-2005-3391)
    a cross-site scripting (XSS) vulnerability in
    phpinfo() (CVE-2005-3388)
  
Impact :

    Attackers could leverage these issues to exploit applications that
    are assumed to be secure through the use of proper register_globals,
    safe_mode or open_basedir parameters. Remote attackers could also
    conduct cross-site scripting attacks if a page calling phpinfo() was
    available. Finally, a local attacker could cause a local Denial of
    Service using malicious session.save_path options.
  
Workaround :

    There is no known workaround that would solve all issues at this
    time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200511-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All PHP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-php/php
    All mod_php users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-php/mod_php
    All php-cgi users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-php/php-cgi"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mod_php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:php-cgi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/15");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/31");
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

if (qpkg_check(package:"dev-php/php-cgi", unaffected:make_list("rge 4.3.11-r5", "ge 4.4.0-r5"), vulnerable:make_list("lt 4.4.0-r5"))) flag++;
if (qpkg_check(package:"dev-php/php", unaffected:make_list("rge 4.3.11-r4", "ge 4.4.0-r4"), vulnerable:make_list("lt 4.4.0-r4"))) flag++;
if (qpkg_check(package:"dev-php/mod_php", unaffected:make_list("rge 4.3.11-r4", "ge 4.4.0-r8"), vulnerable:make_list("lt 4.4.0-r8"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PHP");
}
