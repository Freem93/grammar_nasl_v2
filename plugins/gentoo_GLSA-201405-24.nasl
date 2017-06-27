#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201405-24.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(74066);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/20 14:03:00 $");

  script_cve_id("CVE-2010-1623", "CVE-2011-0419", "CVE-2011-1928", "CVE-2012-0840");
  script_bugtraq_id(43673, 47820, 47929, 51917);
  script_osvdb_id(68327, 73383, 73388);
  script_xref(name:"GLSA", value:"201405-24");

  script_name(english:"GLSA-201405-24 : Apache Portable Runtime, APR Utility Library: Denial of Service");
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
"The remote host is affected by the vulnerability described in GLSA-201405-24
(Apache Portable Runtime, APR Utility Library: Denial of Service)

    Multiple vulnerabilities have been discovered in Apache Portable Runtime
      and APR Utility Library. Please review the CVE identifiers referenced
      below for details.
  
Impact :

    A remote attacker could cause a Denial of Service condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201405-24"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Apache Portable Runtime users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-libs/apr-1.4.8-r1'
    All users of the APR Utility Library should upgrade to the latest
      version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-libs/apr-util-1.3.10'
    Packages which depend on these libraries may need to be recompiled.
      Tools such as revdep-rebuild may assist in identifying some of these
      packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:apr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:apr-util");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/19");
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

if (qpkg_check(package:"dev-libs/apr-util", unaffected:make_list("ge 1.3.10"), vulnerable:make_list("lt 1.3.10"))) flag++;
if (qpkg_check(package:"dev-libs/apr", unaffected:make_list("ge 1.4.8-r1"), vulnerable:make_list("lt 1.4.8-r1"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:qpkg_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Apache Portable Runtime / APR Utility Library");
}
