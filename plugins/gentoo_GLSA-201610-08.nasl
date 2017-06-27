#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201610-08.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(94085);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/19 14:14:42 $");

  script_cve_id("CVE-2016-0402", "CVE-2016-0448", "CVE-2016-0466", "CVE-2016-0475", "CVE-2016-0483", "CVE-2016-0494", "CVE-2016-0603", "CVE-2016-0636", "CVE-2016-3426", "CVE-2016-3458", "CVE-2016-3485", "CVE-2016-3498", "CVE-2016-3500", "CVE-2016-3503", "CVE-2016-3508", "CVE-2016-3511", "CVE-2016-3550", "CVE-2016-3552", "CVE-2016-3587", "CVE-2016-3598", "CVE-2016-3606", "CVE-2016-3610");
  script_xref(name:"GLSA", value:"201610-08");

  script_name(english:"GLSA-201610-08 : Oracle JRE/JDK: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201610-08
(Oracle JRE/JDK: Multiple vulnerabilities)

    Multiple vulnerabilities exist in both Oracle&rsquo;s JRE and JDK. Please
      review the referenced CVE&rsquo;s for additional information.
  
Impact :

    Remote attackers could gain access to information, remotely execute
      arbitrary code, or cause Denial of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201610-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Oracle JRE Users users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-java/oracle-jre-bin-1.8.0.101'
    All Oracle JDK Users users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-java/oracle-jdk-bin-1.8.0.101'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:oracle-jdk-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:oracle-jre-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-java/oracle-jre-bin", unaffected:make_list("ge 1.8.0.101"), vulnerable:make_list("lt 1.8.0.101"))) flag++;
if (qpkg_check(package:"dev-java/oracle-jdk-bin", unaffected:make_list("ge 1.8.0.101"), vulnerable:make_list("lt 1.8.0.101"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Oracle JRE/JDK");
}
