#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201206-13.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(59651);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 13:53:26 $");

  script_cve_id("CVE-2009-0217", "CVE-2010-3332", "CVE-2010-3369", "CVE-2010-4159", "CVE-2010-4225", "CVE-2010-4254", "CVE-2011-0989", "CVE-2011-0990", "CVE-2011-0991", "CVE-2011-0992");
  script_bugtraq_id(35671, 43316, 44351, 44810, 45051, 45711, 47208);
  script_osvdb_id(55895, 55907, 56243, 68127, 68795, 69325, 69619, 70312, 75025, 75026, 75027, 75028);
  script_xref(name:"GLSA", value:"201206-13");

  script_name(english:"GLSA-201206-13 : Mono: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201206-13
(Mono: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Mono and Mono debugger.
      Please review the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could execute arbitrary code, bypass general
      constraints, obtain the source code for .aspx applications, obtain other
      sensitive information, cause a Denial of Service, modify internal data
      structures, or corrupt the internal state of the security manager.
    A local attacker could entice a user into running Mono debugger in a
      directory containing a specially crafted library file to execute
      arbitrary code with the privileges of the user running Mono debugger.
    A context-dependent attacker could bypass the authentication mechanism
      provided by the XML Signature specification.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201206-13"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Mono debugger users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-util/mono-debugger-2.8.1-r1'
    All Mono users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/mono-2.10.2-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mono-debugger");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/22");
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

if (qpkg_check(package:"dev-util/mono-debugger", unaffected:make_list("ge 2.8.1-r1"), vulnerable:make_list("lt 2.8.1-r1"))) flag++;
if (qpkg_check(package:"dev-lang/mono", unaffected:make_list("ge 2.10.2-r1"), vulnerable:make_list("lt 2.10.2-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mono");
}
