#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200406-06.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14517);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/01/14 15:20:32 $");

  script_cve_id("CVE-2004-0414", "CVE-2004-0416", "CVE-2004-0417", "CVE-2004-0418");
  script_osvdb_id(6830, 6831, 6832, 6833, 6834, 6835, 6836);
  script_xref(name:"GLSA", value:"200406-06");

  script_name(english:"GLSA-200406-06 : CVS: additional DoS and arbitrary code execution vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200406-06
(CVS: additional DoS and arbitrary code execution vulnerabilities)

    A team audit of the CVS source code performed by Stefan Esser and Sebastian
    Krahmer resulted in the discovery of several remotely exploitable
    vulnerabilities including:
    no-null-termination of 'Entry' lines
    error_prog_name 'double-free()'
    Argument integer overflow
    serve_notify() out of bounds writes
  
Impact :

    An attacker could use these vulnerabilities to cause a Denial of Service or
    execute arbitrary code with the permissions of the user running cvs.
  
Workaround :

    There is no known workaround at this time. All users are advised to upgrade
    to the latest available version of CVS."
  );
  # http://security.e-matters.de/advisories/092004.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1215cc0e"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200406-06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All CVS users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv '>=dev-util/cvs-1.11.17'
    # emerge '>=dev-util/cvs-1.11.17'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:cvs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-util/cvs", unaffected:make_list("ge 1.11.17"), vulnerable:make_list("le 1.11.16-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "CVS");
}
