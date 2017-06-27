#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201206-24.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(59677);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2008-5515", "CVE-2009-0033", "CVE-2009-0580", "CVE-2009-0781", "CVE-2009-0783", "CVE-2009-2693", "CVE-2009-2901", "CVE-2009-2902", "CVE-2010-1157", "CVE-2010-2227", "CVE-2010-3718", "CVE-2010-4172", "CVE-2010-4312", "CVE-2011-0013", "CVE-2011-0534", "CVE-2011-1088", "CVE-2011-1183", "CVE-2011-1184", "CVE-2011-1419", "CVE-2011-1475", "CVE-2011-1582", "CVE-2011-2204", "CVE-2011-2481", "CVE-2011-2526", "CVE-2011-2729", "CVE-2011-3190", "CVE-2011-3375", "CVE-2011-4858", "CVE-2011-5062", "CVE-2011-5063", "CVE-2011-5064", "CVE-2012-0022");
  script_bugtraq_id(35193, 35196, 35263, 35416, 37942, 37944, 37945, 39635, 41544, 45015, 46164, 46174, 46177, 46685, 47196, 47199, 47886, 48456, 48667, 49143, 49147, 49353, 49762, 51200, 51442, 51447);
  script_osvdb_id(52899, 55053, 55054, 55055, 55056, 62052, 62053, 62054, 64023, 66319, 69456, 69512, 70809, 71027, 71557, 71558, 72407, 73429, 73776, 73797, 73798, 74535, 74541, 74818, 76189, 78113, 78331, 78483, 78573, 78598, 78599, 78600);
  script_xref(name:"GLSA", value:"201206-24");

  script_name(english:"GLSA-201206-24 : Apache Tomcat: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201206-24
(Apache Tomcat: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Apache Tomcat. Please
      review the CVE identifiers referenced below for details.
  
Impact :

    The vulnerabilities allow an attacker to cause a Denial of Service, to
      hijack a session, to bypass authentication, to inject webscript, to
      enumerate valid usernames, to read, modify and overwrite arbitrary files,
      to bypass intended access restrictions, to delete work-directory files,
      to discover the server&rsquo;s hostname or IP, to bypass read permissions for
      files or HTTP headers, to read or write files outside of the intended
      working directory, and to obtain sensitive information by reading a log
      file.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201206-24"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Apache Tomcat 6.0.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-servers/tomcat-6.0.35'
    All Apache Tomcat 7.0.x users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-servers/tomcat-7.0.23'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20, 22, 79, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:tomcat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/25");
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

if (qpkg_check(package:"www-servers/tomcat", unaffected:make_list("rge 6.0.35", "ge 7.0.23", "rge 6.0.44", "rge 6.0.45", "rge 6.0.46", "rge 6.0.47", "rge 6.0.48"), vulnerable:make_list("lt 7.0.23"))) flag++;

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
