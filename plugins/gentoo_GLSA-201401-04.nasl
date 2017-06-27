#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201401-04.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(71811);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/06/18 13:42:57 $");

  script_cve_id("CVE-2010-1634", "CVE-2010-2089", "CVE-2010-3492", "CVE-2010-3493", "CVE-2011-1015", "CVE-2012-0845", "CVE-2012-1150", "CVE-2013-2099");
  script_bugtraq_id(40370, 40863, 44533, 46541, 51239, 51996, 59877);
  script_osvdb_id(64957, 65151, 68738, 68739, 71361, 79249, 80009, 93408);
  script_xref(name:"GLSA", value:"201401-04");

  script_name(english:"GLSA-201401-04 : Python: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201401-04
(Python: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Python. Please review
      the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could possibly cause a Denial of Service condition or
      perform a man-in-the-middle attack to disclose sensitive information.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201401-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Python 3.3 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/python-3.3.2-r1'
    All Python 3.2 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/python-3.2.5-r1'
    All Python 2.6 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/python-2.6.8'
    All Python 2.7 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/python-2.7.3-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-lang/python", unaffected:make_list("rge 3.2.5-r1", "rge 2.6.8", "rge 2.7.3-r1", "ge 3.3.2-r1", "rge 2.6.9", "rge 2.7.4", "rge 2.7.5", "rge 2.7.6", "rge 2.7.7", "rge 2.7.8", "rge 2.7.9", "rge 2.7.10", "rge 2.7.11", "rge 2.7.12", "rge 2.7.13", "rge 2.7.14", "rge 2.7.15"), vulnerable:make_list("lt 3.3.2-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Python");
}
