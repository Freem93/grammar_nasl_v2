#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201412-10.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(79963);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/04/13 14:33:56 $");

  script_cve_id("CVE-2008-4776", "CVE-2010-2713", "CVE-2010-3313", "CVE-2010-3314", "CVE-2011-0765", "CVE-2011-2198", "CVE-2012-0807", "CVE-2012-0808", "CVE-2012-1620", "CVE-2012-2738", "CVE-2012-3448");
  script_bugtraq_id(41716, 46477, 48645, 51574, 52642, 52922, 54281, 54699);
  script_xref(name:"GLSA", value:"201412-10");

  script_name(english:"GLSA-201412-10 : Multiple packages, Multiple vulnerabilities fixed in 2012");
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
"The remote host is affected by the vulnerability described in GLSA-201412-10
(Multiple packages, Multiple vulnerabilities fixed in 2012)

    Vulnerabilities have been discovered in the packages listed below.
      Please review the CVE identifiers in the Reference section for details.
      EGroupware
      VTE
      Layer Four Traceroute (LFT)
      Suhosin
      Slock
      Ganglia
      Jabber to GaduGadu Gateway
  
Impact :

    A context-dependent attacker may be able to gain escalated privileges,
      execute arbitrary code, cause Denial of Service, obtain sensitive
      information, or otherwise bypass security restrictions.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201412-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All EGroupware users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-apps/egroupware-1.8.004.20120613'
    All VTE 0.32 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=x11-libs/vte-0.32.2'
    All VTE 0.28 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=x11-libs/vte-0.28.2-r204'
    All Layer Four Traceroute users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-analyzer/lft-3.33'
    All Suhosin users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-php/suhosin-0.9.33'
    All Slock users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=x11-misc/slock-1.0'
    All Ganglia users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=sys-cluster/ganglia-3.3.7'
    All Jabber to GaduGadu Gateway users should upgrade to the latest
      version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-im/gg-transport-2.2.4'
    NOTE: This is a legacy GLSA. Updates for all affected architectures have
      been available since 2013. It is likely that your system is already no
      longer affected by these issues."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:egroupware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ganglia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gg-transport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:lft");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:slock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:suhosin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:vte");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
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

if (qpkg_check(package:"dev-php/suhosin", unaffected:make_list("ge 0.9.33"), vulnerable:make_list("lt 0.9.33"))) flag++;
if (qpkg_check(package:"net-im/gg-transport", unaffected:make_list("ge 2.2.4"), vulnerable:make_list("lt 2.2.4"))) flag++;
if (qpkg_check(package:"sys-cluster/ganglia", unaffected:make_list("ge 3.3.7"), vulnerable:make_list("lt 3.3.7"))) flag++;
if (qpkg_check(package:"x11-misc/slock", unaffected:make_list("ge 1.0"), vulnerable:make_list("lt 1.0"))) flag++;
if (qpkg_check(package:"www-apps/egroupware", unaffected:make_list("ge 1.8.004.20120613"), vulnerable:make_list("lt 1.8.004.20120613"))) flag++;
if (qpkg_check(package:"net-analyzer/lft", unaffected:make_list("ge 3.33"), vulnerable:make_list("lt 3.33"))) flag++;
if (qpkg_check(package:"x11-libs/vte", unaffected:make_list("ge 0.32.2", "rge 0.28.2-r204", "rge 0.28.2-r206"), vulnerable:make_list("lt 0.32.2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dev-php/suhosin / net-im/gg-transport / sys-cluster/ganglia / etc");
}
