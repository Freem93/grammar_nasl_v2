#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201201-01.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(57433);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/16 13:53:25 $");

  script_cve_id("CVE-2008-7251", "CVE-2008-7252", "CVE-2010-2958", "CVE-2010-3055", "CVE-2010-3056", "CVE-2010-3263", "CVE-2011-0986", "CVE-2011-0987", "CVE-2011-2505", "CVE-2011-2506", "CVE-2011-2507", "CVE-2011-2508", "CVE-2011-2642", "CVE-2011-2643", "CVE-2011-2718", "CVE-2011-2719", "CVE-2011-3646", "CVE-2011-4064", "CVE-2011-4107", "CVE-2011-4634", "CVE-2011-4780", "CVE-2011-4782");
  script_bugtraq_id(37826, 42584, 42591, 42874, 46359, 48563, 48874, 50175, 50497, 51099, 51166, 51226);
  script_osvdb_id(61859, 61860, 67310, 67316, 67317, 67318, 67319, 67320, 67321, 67322, 67323, 67324, 67325, 67343, 67485, 67486, 67487, 67488, 67489, 67490, 67491, 67741, 67851, 70962, 72915, 73611, 73612, 73613, 73614, 74109, 74110, 74111, 74112, 76711, 76798, 77103, 77983, 78029, 78030, 78031, 78032, 78033, 78034, 78036);
  script_xref(name:"GLSA", value:"201201-01");
  script_xref(name:"TRA", value:"TRA-2010-02");

  script_name(english:"GLSA-201201-01 : phpMyAdmin: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201201-01
(phpMyAdmin: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in phpMyAdmin. Please
      review the CVE identifiers and phpMyAdmin Security Advisories referenced
      below for details.
  
Impact :

    Remote attackers might be able to insert and execute PHP code, include
      and execute local PHP files, or perform Cross-Site Scripting (XSS)
      attacks via various vectors.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2010-1.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2010-2.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2010-4.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2010-5.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2010-6.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2010-7.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-1.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-10.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-11.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-12.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-15.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-16.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-17.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-18.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-19.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-2.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-20.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-5.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-6.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-7.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-8.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-9.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201201-01"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2010-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All phpMyAdmin users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/phpmyadmin-3.4.9'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Phpmyadmin 3.x RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:phpmyadmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-db/phpmyadmin", unaffected:make_list("ge 3.4.9"), vulnerable:make_list("lt 3.4.9"))) flag++;

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
