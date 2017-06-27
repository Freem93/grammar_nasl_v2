#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200606-06.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(21667);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/04/13 13:49:35 $");

  script_cve_id("CVE-2006-1945", "CVE-2006-2237");
  script_osvdb_id(24745, 25284);
  script_xref(name:"GLSA", value:"200606-06");

  script_name(english:"GLSA-200606-06 : AWStats: Remote execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-200606-06
(AWStats: Remote execution of arbitrary code)

    Hendrik Weimer has found that if updating the statistics via the
    web frontend is enabled, it is possible to inject arbitrary code via a
    pipe character in the 'migrate' parameter. Additionally, r0t has
    discovered that AWStats fails to properly sanitize user-supplied input
    in awstats.pl.
  
Impact :

    A remote attacker can execute arbitrary code on the server in the
    context of the application running the AWStats CGI script if updating
    of the statistics via web frontend is allowed. Nonetheless, all
    configurations are affected by a cross-site scripting vulnerability in
    awstats.pl, allowing a remote attacker to execute arbitrary scripts
    running in the context of the victim's browser.
  
Workaround :

    Disable statistics updates using the web frontend to avoid code
    injection. However, there is no known workaround at this time
    concerning the cross-site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200606-06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All AWStats users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-misc/awstats-6.5-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'AWStats migrate Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:awstats");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/08");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-misc/awstats", unaffected:make_list("ge 6.5-r1"), vulnerable:make_list("lt 6.5-r1"))) flag++;

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
