#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200501-36.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(16427);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/04/13 13:41:57 $");

  script_cve_id("CVE-2005-0116", "CVE-2005-0362", "CVE-2005-0363");
  script_osvdb_id(13002);
  script_xref(name:"GLSA", value:"200501-36");

  script_name(english:"GLSA-200501-36 : AWStats: Remote code execution");
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
"The remote host is affected by the vulnerability described in GLSA-200501-36
(AWStats: Remote code execution)

    When 'awstats.pl' is run as a CGI script, it fails to validate specific
    inputs which are used in a Perl open() function call. Furthermore, a
    user could read log file content even when plugin rawlog was not
    enabled.
  
Impact :

    A remote attacker could supply AWStats malicious input, potentially
    allowing the execution of arbitrary code with the rights of the web
    server. He could also access raw log contents.
  
Workaround :

    Making sure that AWStats does not run as a CGI script will avoid the
    issue, but we recommend that users upgrade to the latest version, which
    fixes these bugs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://awstats.sourceforge.net/docs/awstats_changelog.txt"
  );
  # http://www.idefense.com/application/poi/display?id=185
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?020e4b8e"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200501-36"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All AWStats users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-misc/awstats-6.3-r2'
    Note: Users with the vhosts USE flag set should manually use
    webapp-config to finalize the update."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'AWStats configdir Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:awstats");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/01");
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

if (qpkg_check(package:"www-misc/awstats", unaffected:make_list("ge 6.3-r2"), vulnerable:make_list("lt 6.3-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "AWStats");
}
