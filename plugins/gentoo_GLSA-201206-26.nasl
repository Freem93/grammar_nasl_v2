#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201206-26.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(59679);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/16 13:53:26 $");

  script_cve_id("CVE-2010-2059", "CVE-2010-2197", "CVE-2010-2198", "CVE-2010-2199", "CVE-2011-3378", "CVE-2012-0060", "CVE-2012-0061", "CVE-2012-0815");
  script_bugtraq_id(40512, 49799, 52865);
  script_osvdb_id(65143, 65144, 66943, 75930, 75931, 81009, 81010, 81011, 83222, 83269);
  script_xref(name:"GLSA", value:"201206-26");

  script_name(english:"GLSA-201206-26 : RPM: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201206-26
(RPM: Multiple vulnerabilities)

    Multiple vulnerabilities have been found in RPM:
      fsm.c fails to properly strip setuid and setgid bits from executable
        files during a package upgrade (CVE-2010-2059).
      RPM does not properly parse spec files (CVE-2010-2197).
      fsm.c fails to properly strip POSIX file capabilities from executable
        files during a package upgrade or removal (CVE-2010-2198).
      fsm.c fails to properly strip POSIX ACLs from executable files during
        a package upgrade or removal (CVE-2010-2199).
      header.c does not properly parse region offsets in package files
        (CVE-2011-3378).
      RPM does not properly sanitize region tags in package headers
        (CVE-2012-0060).
      RPM does not properly sanitize region sizes in package headers
        (CVE-2012-0061).
      RPM does not properly sanitize region offsets in package
        headers(CVE-2012-0815).
  
Impact :

    A local attacker may be able to gain elevated privileges. Furthermore, a
      remote attacker could entice a user to open a specially crafted RPM
      package, possibly resulting in execution of arbitrary code with the
      privileges of the process or a Denial of Service condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201206-26"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All RPM users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-arch/rpm-4.9.1.3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:rpm");
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

if (qpkg_check(package:"app-arch/rpm", unaffected:make_list("ge 4.9.1.3"), vulnerable:make_list("lt 4.9.1.3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "RPM");
}
