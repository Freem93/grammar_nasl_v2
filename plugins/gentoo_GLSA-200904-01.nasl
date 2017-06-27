#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200904-01.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(36078);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2008-6508", "CVE-2008-6509", "CVE-2008-6510", "CVE-2008-6511", "CVE-2009-0496", "CVE-2009-0497");
  script_bugtraq_id(32189, 32935, 32937, 32938, 32939, 32940, 32943, 32944, 32945);
  script_osvdb_id(49663, 51419, 51420, 51421, 51422, 51423, 51424, 51425, 51426, 51912, 52902, 52903);
  script_xref(name:"GLSA", value:"200904-01");

  script_name(english:"GLSA-200904-01 : Openfire: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200904-01
(Openfire: Multiple vulnerabilities)

    Two vulnerabilities have been reported by Federico Muttis, from CORE
    IMPACT's Exploit Writing Team:
    Multiple missing or incomplete input validations in several .jsps
    (CVE-2009-0496).
    Incorrect input validation of the 'log' parameter in log.jsp
    (CVE-2009-0497).
    Multiple vulnerabilities have been reported by Andreas Kurtz:
    Erroneous built-in exceptions to input validation in login.jsp
    (CVE-2008-6508).
    Unsanitized user input to the 'type' parameter in
    sipark-log-summary.jsp used in SQL statement. (CVE-2008-6509)
    A Cross-Site-Scripting vulnerability due to unsanitized input to the
    'url' parameter. (CVE-2008-6510, CVE-2008-6511)
  
Impact :

    A remote attacker could execute arbitrary code on clients' systems by
    uploading a specially crafted plugin, bypassing authentication.
    Additionally, an attacker could read arbitrary files on the server or
    execute arbitrary SQL statements. Depending on the server's
    configuration the attacker might also execute code on the server via an
    SQL injection.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200904-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Openfire users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-im/openfire-3.6.3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Openfire Admin Console Authentication Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 22, 79, 89);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openfire");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/03");
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

if (qpkg_check(package:"net-im/openfire", unaffected:make_list("ge 3.6.3"), vulnerable:make_list("lt 3.6.3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Openfire");
}
