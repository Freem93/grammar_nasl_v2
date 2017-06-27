#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200504-15.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(18081);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:41:58 $");

  script_cve_id("CVE-2005-0524", "CVE-2005-0525", "CVE-2005-1042", "CVE-2005-1043");
  script_osvdb_id(15183, 15184, 15629, 15630);
  script_xref(name:"GLSA", value:"200504-15");

  script_name(english:"GLSA-200504-15 : PHP: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200504-15
(PHP: Multiple vulnerabilities)

    An integer overflow and an unbound recursion were discovered in
    the processing of Image File Directory tags in PHP's EXIF module
    (CAN-2005-1042, CAN-2005-1043). Furthermore, two infinite loops have
    been discovered in the getimagesize() function when processing IFF or
    JPEG images (CAN-2005-0524, CAN-2005-0525).
  
Impact :

    A remote attacker could craft an image file with a malicious EXIF
    IFD tag, a large IFD nesting level or invalid size parameters and send
    it to a web application that would process this user-provided image
    using one of the affected functions. This could result in denying
    service on the attacked server and potentially executing arbitrary code
    with the rights of the web server.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/release_4_3_11.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200504-15"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All PHP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-php/php-4.3.11'
    All mod_php users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-php/mod_php-4.3.11'
    All php-cgi users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-php/php-cgi-4.3.11'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mod_php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:php-cgi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/31");
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

if (qpkg_check(package:"dev-php/php-cgi", unaffected:make_list("ge 4.3.11"), vulnerable:make_list("lt 4.3.11"))) flag++;
if (qpkg_check(package:"dev-php/php", unaffected:make_list("ge 4.3.11"), vulnerable:make_list("lt 4.3.11"))) flag++;
if (qpkg_check(package:"dev-php/mod_php", unaffected:make_list("ge 4.3.11"), vulnerable:make_list("lt 4.3.11"))) flag++;

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
