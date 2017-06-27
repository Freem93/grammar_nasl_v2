#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201406-14.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(76065);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/04/13 14:27:08 $");

  script_cve_id("CVE-2012-6461", "CVE-2012-6462", "CVE-2012-6463", "CVE-2012-6464", "CVE-2012-6465", "CVE-2012-6466", "CVE-2012-6467", "CVE-2012-6468", "CVE-2012-6469", "CVE-2012-6470", "CVE-2012-6471", "CVE-2012-6472", "CVE-2013-1618", "CVE-2013-1637", "CVE-2013-1638", "CVE-2013-1639");
  script_bugtraq_id(56407, 56594, 56788, 56980, 56984, 57120, 57121, 57132, 57633, 57773);
  script_xref(name:"GLSA", value:"201406-14");

  script_name(english:"GLSA-201406-14 : Opera: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201406-14
(Opera: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Opera. Please review
      the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could entice a user to open a specially crafted web
      page using Opera, possibly resulting in execution of arbitrary code with
      the privileges of the process or a Denial of Service condition.
      Furthermore, a remote attacker may be able to obtain sensitive
      information, conduct Cross-Site Scripting (XSS) attacks, or bypass
      security restrictions.
    A local attacker may be able to obtain sensitive information.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201406-14"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Opera users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/opera-12.13_p1734'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/16");
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

if (qpkg_check(package:"www-client/opera", unaffected:make_list("ge 12.13_p1734"), vulnerable:make_list("lt 12.13_p1734"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Opera");
}
