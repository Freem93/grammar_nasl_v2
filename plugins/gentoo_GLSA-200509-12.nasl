#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200509-12.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(19811);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/11 13:32:17 $");

  script_cve_id("CVE-2005-2491", "CVE-2005-2700");
  script_bugtraq_id(14620);
  script_osvdb_id(18906, 19188);
  script_xref(name:"GLSA", value:"200509-12");

  script_name(english:"GLSA-200509-12 : Apache, mod_ssl: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200509-12
(Apache, mod_ssl: Multiple vulnerabilities)

    mod_ssl contains a security issue when 'SSLVerifyClient optional' is
    configured in the global virtual host configuration (CAN-2005-2700).
    Also, Apache's httpd includes a PCRE library, which makes it vulnerable
    to an integer overflow (CAN-2005-2491).
  
Impact :

    Under a specific configuration, mod_ssl does not properly enforce the
    client-based certificate authentication directive, 'SSLVerifyClient
    require', in a per-location context, which could be potentially used by
    a remote attacker to bypass some restrictions. By creating a specially
    crafted '.htaccess' file, a local attacker could possibly exploit
    Apache's vulnerability, which would result in a local privilege
    escalation.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200509-12"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All mod_ssl users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-www/mod_ssl-2.8.24'
    All Apache 2 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-servers/apache-2.0.54-r15'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-servers/apache", unaffected:make_list("ge 2.0.54-r15", "lt 2"), vulnerable:make_list("lt 2.0.54-r15"))) flag++;
if (qpkg_check(package:"net-www/mod_ssl", unaffected:make_list("ge 2.8.24"), vulnerable:make_list("lt 2.8.24"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Apache / mod_ssl");
}
