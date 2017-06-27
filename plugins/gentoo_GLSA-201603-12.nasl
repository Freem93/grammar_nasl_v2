#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201603-12.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(89905);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/03/14 14:55:46 $");

  script_cve_id("CVE-2012-2090", "CVE-2012-2091");
  script_xref(name:"GLSA", value:"201603-12");

  script_name(english:"GLSA-201603-12 : FlightGear, SimGear: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201603-12
(FlightGear, SimGear: Multiple vulnerabilities)

    Multiple format string vulnerabilities in FlightGear and SimGear allow
      user-assisted remote attackers to cause a denial of service and possibly
      execute arbitrary code via format string specifiers in certain data chunk
      values in an aircraft xml model.
  
Impact :

    Remote attackers could possibly execute arbitrary code or cause Denial
      of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201603-12"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Flightgear users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=games-simulation/flightgear-3.4.0'
    All Simgear users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=games-simulation/simgear-3.4.0'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:flightgear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:simgear");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/14");
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

if (qpkg_check(package:"games-simulation/simgear", unaffected:make_list("ge 3.4.0"), vulnerable:make_list("lt 3.4.0"))) flag++;
if (qpkg_check(package:"games-simulation/flightgear", unaffected:make_list("ge 3.4.0"), vulnerable:make_list("lt 3.4.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "FlightGear / SimGear");
}
