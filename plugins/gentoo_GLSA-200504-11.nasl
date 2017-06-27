#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200504-11.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(18044);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:41:58 $");

  script_cve_id("CVE-2005-1108", "CVE-2005-1109");
  script_osvdb_id(15502, 15503);
  script_xref(name:"GLSA", value:"200504-11");

  script_name(english:"GLSA-200504-11 : JunkBuster: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200504-11
(JunkBuster: Multiple vulnerabilities)

    James Ranson reported a vulnerability when JunkBuster is configured to
    run in single-threaded mode, an attacker can modify the referrer
    setting by getting a victim to request a specially crafted URL
    (CAN-2005-1108). Tavis Ormandy of the Gentoo Linux Security Audit Team
    identified a heap corruption issue in the filtering of URLs
    (CAN-2005-1109).
  
Impact :

    If JunkBuster has been configured to run in single-threaded mode, an
    attacker can disable or modify the filtering of Referrer: HTTP headers,
    potentially compromising the privacy of users. The heap corruption
    vulnerability could crash or disrupt the operation of the proxy,
    potentially executing arbitrary code.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200504-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All JunkBuster users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-proxy/junkbuster-2.0.2-r3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:junkbuster");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-proxy/junkbuster", unaffected:make_list("ge 2.0.2-r3"), vulnerable:make_list("lt 2.0.2-r3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "JunkBuster");
}
