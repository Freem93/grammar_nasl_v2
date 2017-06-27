#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200508-07.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(19440);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/04/13 13:49:33 $");

  script_cve_id("CVE-2005-1527");
  script_osvdb_id(18696);
  script_xref(name:"GLSA", value:"200508-07");

  script_name(english:"GLSA-200508-07 : AWStats: Arbitrary code execution using malicious Referrer information");
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
"The remote host is affected by the vulnerability described in GLSA-200508-07
(AWStats: Arbitrary code execution using malicious Referrer information)

    When using a URLPlugin, AWStats fails to sanitize Referrer URL
    data before using them in a Perl eval() routine.
  
Impact :

    A remote attacker can include arbitrary Referrer information in a
    HTTP request to a web server, therefore injecting tainted data in the
    log files. When AWStats is run on this log file, this can result in the
    execution of arbitrary Perl code with the rights of the user running
    AWStats.
  
Workaround :

    Disable all URLPlugins in the AWStats configuration."
  );
  # http://www.idefense.com/application/poi/display?id=290&type=vulnerabilities
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?21540da6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200508-07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All AWStats users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-misc/awstats-6.5'
    Note: Users with the vhosts USE flag set should manually use
    webapp-config to finalize the update."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:awstats");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/09");
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

if (qpkg_check(package:"www-misc/awstats", unaffected:make_list("ge 6.5"), vulnerable:make_list("lt 6.5"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "AWStats");
}
