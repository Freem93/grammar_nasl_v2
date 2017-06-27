#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201412-29.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(79982);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/20 14:03:00 $");

  script_cve_id("CVE-2012-2733", "CVE-2012-3544", "CVE-2012-3546", "CVE-2012-4431", "CVE-2012-4534", "CVE-2012-5885", "CVE-2012-5886", "CVE-2012-5887", "CVE-2013-2067", "CVE-2013-2071", "CVE-2013-4286", "CVE-2013-4322", "CVE-2013-4590", "CVE-2014-0033", "CVE-2014-0050", "CVE-2014-0075", "CVE-2014-0096", "CVE-2014-0099", "CVE-2014-0119");
  script_bugtraq_id(56402, 56403, 56812, 56813, 56814, 59797, 59798, 59799, 65400, 65767, 65768, 65769, 65773, 67667, 67668, 67669, 67671);
  script_xref(name:"GLSA", value:"201412-29");

  script_name(english:"GLSA-201412-29 : Apache Tomcat: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201412-29
(Apache Tomcat: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Tomcat. Please review
      the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker may be able to cause a Denial of Service condition as
      well as obtain sensitive information, bypass protection mechanisms and
      authentication restrictions.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201412-29"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Tomcat 6.0.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-servers/tomcat-6.0.41'
    All Tomcat 7.0.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-servers/tomcat-7.0.56'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:tomcat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-servers/tomcat", unaffected:make_list("ge 7.0.56", "rge 6.0.41", "rge 6.0.42", "rge 6.0.43", "rge 6.0.44", "rge 6.0.45", "rge 6.0.46", "rge 6.0.47", "rge 6.0.48"), vulnerable:make_list("lt 7.0.56"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Apache Tomcat");
}
