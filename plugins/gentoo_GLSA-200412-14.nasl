#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200412-14.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(16001);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/06/24 14:42:21 $");

  script_cve_id("CVE-2004-1019", "CVE-2004-1020", "CVE-2004-1063", "CVE-2004-1064", "CVE-2004-1065");
  script_osvdb_id(12410, 12411, 12412, 12413, 12415, 12600);
  script_xref(name:"GLSA", value:"200412-14");

  script_name(english:"GLSA-200412-14 : PHP: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200412-14
(PHP: Multiple vulnerabilities)

    Stefan Esser and Marcus Boerger reported several different issues in
    the unserialize() function, including serious exploitable bugs in the
    way it handles negative references (CAN-2004-1019).
    Stefan Esser also discovered that the pack() and unpack() functions are
    subject to integer overflows that can lead to a heap buffer overflow
    and a heap information leak. Finally, he found that the way
    multithreaded PHP handles safe_mode_exec_dir restrictions can be
    bypassed, and that various path truncation issues also allow to bypass
    path and safe_mode restrictions.
    Ilia Alshanetsky found a stack overflow issue in the exif_read_data()
    function (CAN-2004-1065). Finally, Daniel Fabian found that addslashes
    and magic_quotes_gpc do not properly escape null characters and that
    magic_quotes_gpc contains a bug that could lead to one level directory
    traversal.
  
Impact :

    These issues could be exploited by a remote attacker to retrieve web
    server heap information, bypass safe_mode or path restrictions and
    potentially execute arbitrary code with the rights of the web server
    running a PHP application.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/release_4_3_10.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.hardened-php.net/advisories/012004.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/384663/2004-12-15/2004-12-21/0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200412-14"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All PHP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-php/php-4.3.10'
    All mod_php users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-php/mod_php-4.3.10'
    All php-cgi users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-php/php-cgi-4.3.10'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mod_php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:php-cgi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/19");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-php/php-cgi", unaffected:make_list("ge 4.3.10"), vulnerable:make_list("lt 4.3.10"))) flag++;
if (qpkg_check(package:"dev-php/php", unaffected:make_list("ge 4.3.10"), vulnerable:make_list("lt 4.3.10"))) flag++;
if (qpkg_check(package:"dev-php/mod_php", unaffected:make_list("ge 4.3.10"), vulnerable:make_list("lt 4.3.10"))) flag++;

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
