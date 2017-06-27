#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201309-11.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(70084);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/04/13 14:19:46 $");

  script_cve_id("CVE-2010-4539", "CVE-2010-4644", "CVE-2011-0715", "CVE-2011-1752", "CVE-2011-1783", "CVE-2011-1921", "CVE-2013-1845", "CVE-2013-1846", "CVE-2013-1847", "CVE-2013-1849", "CVE-2013-1884", "CVE-2013-1968", "CVE-2013-2088", "CVE-2013-2112", "CVE-2013-4131", "CVE-2013-4277");
  script_bugtraq_id(45655, 46734, 48091, 58323, 58895, 58896, 58897, 58898, 60264, 60265, 60267, 61454, 62266);
  script_osvdb_id(70332, 70333, 70964, 73245, 73246, 73247, 92090, 92091, 92092, 92093, 92094, 93793, 93794, 93795, 93796, 95885, 96931);
  script_xref(name:"GLSA", value:"201309-11");

  script_name(english:"GLSA-201309-11 : Subversion: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201309-11
(Subversion: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Subversion. Please
      review the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could cause a Denial of Service condition or obtain
      sensitive information. A local attacker could escalate his privileges to
      the user running svnserve.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201309-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Subversion users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-vcs/subversion-1.7.13'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-vcs/subversion", unaffected:make_list("ge 1.7.13"), vulnerable:make_list("lt 1.7.13"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Subversion");
}
