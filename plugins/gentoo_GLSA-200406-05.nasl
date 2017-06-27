#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200406-05.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14516);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:34:21 $");

  script_cve_id("CVE-2004-0488");
  script_osvdb_id(6472);
  script_xref(name:"GLSA", value:"200406-05");

  script_name(english:"GLSA-200406-05 : Apache: Buffer overflow in mod_ssl");
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
"The remote host is affected by the vulnerability described in GLSA-200406-05
(Apache: Buffer overflow in mod_ssl)

    A bug in the function ssl_util_uuencode_binary in ssl_util.c may lead to a
    remote buffer overflow on a server configured to use FakeBasicAuth that
    will trust a client certificate with an issuing CA with a subject DN longer
    than 6k.
  
Impact :

    Given the right server configuration, an attacker could cause a Denial of
    Service or execute code as the user running Apache, usually
    'apache'. It is thought to be impossible to exploit this to
    execute code on the x86 platform, but the possibility for other platforms
    is unknown. This does not preclude a DoS on x86 systems.
  
Workaround :

    A server should not be vulnerable if it is not configured to use
    FakeBasicAuth and to trust a client CA with a long subject DN."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200406-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Apache 1.x users should upgrade to the latest version of mod_ssl:
    # emerge sync
    # emerge -pv '>=net-www/mod_ssl-2.8.18'
    # emerge '>=net-www/mod_ssl-2.8.18'
    Apache 2.x users should upgrade to the latest version of Apache:
    # emerge sync
    # emerge -pv '>=www-servers/apache-2.0.49-r3'
    # emerge '>=www-servers/apache-2.0.49-r3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-servers/apache", unaffected:make_list("lt 2.0", "ge 2.0.49-r3"), vulnerable:make_list("le 2.0.49-r2"))) flag++;
if (qpkg_check(package:"net-www/mod_ssl", unaffected:make_list("ge 2.8.18"), vulnerable:make_list("lt 2.8.18"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Apache");
}
