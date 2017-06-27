#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201206-01.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(59629);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/08/31 14:21:56 $");

  script_cve_id("CVE-2010-3613", "CVE-2010-3614", "CVE-2010-3615", "CVE-2010-3762", "CVE-2011-0414", "CVE-2011-1910", "CVE-2011-2464", "CVE-2011-2465", "CVE-2011-4313");
  script_osvdb_id(68271, 69558, 69559, 69568, 72539, 72540, 73604, 73605, 77159);
  script_xref(name:"GLSA", value:"201206-01");

  script_name(english:"GLSA-201206-01 : BIND: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201206-01
(BIND: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in BIND. Please review the
      CVE identifiers referenced below for details.
  
Impact :

    The vulnerabilities allow remote attackers to cause a Denial of Service
      (daemon crash) via a DNS query, to bypass intended access restrictions,
      to incorrectly cache a ncache entry and a rrsig for the same type and to
      incorrectly mark zone data as insecure.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201206-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All bind users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-dns/bind-9.7.4_p1'
    NOTE: This is a legacy GLSA. Updates for all affected architectures are
      available since December 22, 2011. It is likely that your system is
      already
      no longer affected by this issue."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:bind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-dns/bind", unaffected:make_list("ge 9.7.4_p1"), vulnerable:make_list("lt 9.7.4_p1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "BIND");
}
