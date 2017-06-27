#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201611-04.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(94595);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/11/07 17:42:52 $");

  script_cve_id("CVE-2016-5542", "CVE-2016-5554", "CVE-2016-5556", "CVE-2016-5568", "CVE-2016-5573", "CVE-2016-5582", "CVE-2016-5597");
  script_xref(name:"GLSA", value:"201611-04");

  script_name(english:"GLSA-201611-04 : Oracle JRE/JDK: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201611-04
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
    value:"https://security.gentoo.org/glsa/201611-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Oracle JRE Users users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=dev-java/oracle-jre-bin-1.8.0.111'
    All Oracle JDK Users users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=dev-java/oracle-jdk-bin-1.8.0.111'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:oracle-jdk-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:oracle-jre-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/07");
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

if (qpkg_check(package:"dev-java/oracle-jre-bin", unaffected:make_list("ge 1.8.0.111"), vulnerable:make_list("lt 1.8.0.111"))) flag++;
if (qpkg_check(package:"dev-java/oracle-jdk-bin", unaffected:make_list("ge 1.8.0.111"), vulnerable:make_list("lt 1.8.0.111"))) flag++;

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
