#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200506-20.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(18547);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/04/13 13:41:59 $");

  script_cve_id("CVE-2005-1524", "CVE-2005-1525", "CVE-2005-1526");
  script_osvdb_id(17424, 17425, 17426);
  script_xref(name:"GLSA", value:"200506-20");

  script_name(english:"GLSA-200506-20 : Cacti: Several vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200506-20
(Cacti: Several vulnerabilities)

    Cacti fails to properly sanitize input which can lead to SQL injection,
    authentication bypass as well as PHP file inclusion.
  
Impact :

    An attacker could potentially exploit the file inclusion to execute
    arbitrary code with the permissions of the web server. An attacker
    could exploit these vulnerabilities to bypass authentication or inject
    SQL queries to gain information from the database. Only systems with
    register_globals set to 'On' are affected by the file inclusion and
    authentication bypass vulnerabilities. Gentoo Linux ships with
    register_globals set to 'Off' by default.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.cacti.net/release_notes_0_8_6e.php"
  );
  # http://www.idefense.com/application/poi/display?id=267&type=vulnerabilities&flashstatus=false
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?91c98a8a"
  );
  # http://www.idefense.com/application/poi/display?id=266&type=vulnerabilities&flashstatus=false
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d5e7aa8"
  );
  # http://www.idefense.com/application/poi/display?id=265&type=vulnerabilities&flashstatus=false
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f6cb3782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.cacti.net/release_notes_0_8_6f.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.hardened-php.net/advisory-032005.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.hardened-php.net/advisory-042005.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.hardened-php.net/advisory-052005.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200506-20"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Cacti users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-analyzer/cacti-0.8.6f'
    Note: Users with the vhosts USE flag set should manually use
    webapp-config to finalize the update."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:cacti");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/22");
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

if (qpkg_check(package:"net-analyzer/cacti", unaffected:make_list("ge 0.8.6f"), vulnerable:make_list("lt 0.8.6f"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Cacti");
}
