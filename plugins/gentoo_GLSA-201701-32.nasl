#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201701-32.
#
# The advisory text is Copyright (C) 2001-2017 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(96426);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/01/12 14:54:53 $");

  script_cve_id("CVE-2016-4412", "CVE-2016-5097", "CVE-2016-5098", "CVE-2016-5099", "CVE-2016-5701", "CVE-2016-5702", "CVE-2016-5703", "CVE-2016-5704", "CVE-2016-5705", "CVE-2016-5706", "CVE-2016-5730", "CVE-2016-5731", "CVE-2016-5732", "CVE-2016-5733", "CVE-2016-5734", "CVE-2016-5739", "CVE-2016-6606", "CVE-2016-6607", "CVE-2016-6608", "CVE-2016-6609", "CVE-2016-6610", "CVE-2016-6611", "CVE-2016-6612", "CVE-2016-6613", "CVE-2016-6614", "CVE-2016-6615", "CVE-2016-6616", "CVE-2016-6617", "CVE-2016-6618", "CVE-2016-6619", "CVE-2016-6620", "CVE-2016-6622", "CVE-2016-6623", "CVE-2016-6624", "CVE-2016-6625", "CVE-2016-6626", "CVE-2016-6627", "CVE-2016-6628", "CVE-2016-6629", "CVE-2016-6630", "CVE-2016-6631", "CVE-2016-6632", "CVE-2016-6633", "CVE-2016-9847", "CVE-2016-9848", "CVE-2016-9849", "CVE-2016-9850", "CVE-2016-9851", "CVE-2016-9852", "CVE-2016-9853", "CVE-2016-9854", "CVE-2016-9855", "CVE-2016-9856", "CVE-2016-9857", "CVE-2016-9858", "CVE-2016-9859", "CVE-2016-9860", "CVE-2016-9861", "CVE-2016-9862", "CVE-2016-9863", "CVE-2016-9864", "CVE-2016-9865", "CVE-2016-9866");
  script_xref(name:"GLSA", value:"201701-32");

  script_name(english:"GLSA-201701-32 : phpMyAdmin: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201701-32
(phpMyAdmin: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in phpMyAdmin. Please
      review the CVE identifiers referenced below for details.
  
Impact :

    A authenticated remote attacker could exploit these vulnerabilities to
      execute arbitrary PHP Code, inject SQL code, or to conduct Cross-Site
      Scripting attacks.
    In certain configurations, an unauthenticated remote attacker could
      cause a Denial of Service condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201701-32"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All phpMyAdmin users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/phpmyadmin-4.6.5.1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:phpmyadmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/12");
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

if (qpkg_check(package:"dev-db/phpmyadmin", unaffected:make_list("ge 4.6.5.1"), vulnerable:make_list("lt 4.6.5.1"))) flag++;

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
