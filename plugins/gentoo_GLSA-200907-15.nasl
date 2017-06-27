#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200907-15.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(39869);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2008-5027", "CVE-2008-5028", "CVE-2008-6373", "CVE-2009-2288");
  script_bugtraq_id(35464);
  script_osvdb_id(49991, 49994, 50239, 50240, 50241, 50242, 50457, 55281);
  script_xref(name:"GLSA", value:"200907-15");

  script_name(english:"GLSA-200907-15 : Nagios: Execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-200907-15
(Nagios: Execution of arbitrary code)

    Multiple vulnerabilities have been reported in Nagios:
    Paul reported that statuswml.cgi does not properly sanitize shell
    metacharacters in the (1) ping and (2) traceroute parameters
    (CVE-2009-2288).
    Nagios does not properly verify whether an authenticated user is
    authorized to run certain commands (CVE-2008-5027).
    Andreas Ericsson reported that Nagios does not perform validity checks
    to verify HTTP requests, leading to Cross-Site Request Forgery
    (CVE-2008-5028).
    An unspecified vulnerability in Nagios related to CGI programs,
    'adaptive external commands,' and 'writing newlines and submitting
    service comments' has been reported (CVE-2008-6373).
  
Impact :

    A remote authenticated or unauthenticated attacker may exploit these
    vulnerabilities to execute arbitrary commands or elevate privileges.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200907-15"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Nagios users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-analyzer/nagios-core-3.0.6-r2'
    NOTE: Users of the Nagios 2 branch can update to version 2.12-r1 which
    contains a patch to fix CVE-2009-2288. However, that branch is not
    supported upstream or in Gentoo and we are unaware whether the other
    vulnerabilities affect 2.x installations."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Nagios 3.1.0 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Nagios3 statuswml.cgi Ping Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(78, 94, 264, 352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:nagios-core");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-analyzer/nagios-core", unaffected:make_list("ge 3.0.6-r2"), vulnerable:make_list("lt 3.0.6-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Nagios");
}
