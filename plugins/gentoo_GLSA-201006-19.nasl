#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201006-19.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(46808);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2008-4437", "CVE-2008-6098", "CVE-2009-0481", "CVE-2009-0482", "CVE-2009-0483", "CVE-2009-0484", "CVE-2009-0485", "CVE-2009-0486", "CVE-2009-1213", "CVE-2009-3125", "CVE-2009-3165", "CVE-2009-3166", "CVE-2009-3387", "CVE-2009-3989");
  script_bugtraq_id(30661, 32178, 34308, 36371, 36373, 38025, 38026);
  script_osvdb_id(47547, 49731, 53069, 54051, 54052, 54053, 54054, 54055, 54056, 54057, 58087, 58088, 58089, 62148, 62149);
  script_xref(name:"GLSA", value:"201006-19");

  script_name(english:"GLSA-201006-19 : Bugzilla: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201006-19
(Bugzilla: Multiple vulnerabilities)

    Multiple vulnerabilities have been reported in Bugzilla. Please review
    the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker might be able to disclose local files, bug
    information, passwords, and other data under certain circumstances.
    Furthermore, a remote attacker could conduct SQL injection, Cross-Site
    Scripting (XSS) or Cross-Site Request Forgery (CSRF) attacks via
    various vectors.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201006-19"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Bugzilla users should upgrade to an unaffected version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/bugzilla-3.2.6'
    Bugzilla 2.x and 3.0 have reached their end of life. There will be no
    more security updates. All Bugzilla 2.x and 3.0 users should update to
    a supported Bugzilla 3.x version."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 79, 89, 255, 264, 352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:bugzilla");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-apps/bugzilla", unaffected:make_list("ge 3.2.6"), vulnerable:make_list("lt 3.2.6"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Bugzilla");
}
