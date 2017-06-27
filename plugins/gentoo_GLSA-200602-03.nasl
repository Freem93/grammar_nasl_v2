#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200602-03.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(20874);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/16 13:53:25 $");

  script_cve_id("CVE-2005-3352", "CVE-2005-3357");
  script_bugtraq_id(15834, 16152);
  script_osvdb_id(21705, 22261);
  script_xref(name:"GLSA", value:"200602-03");

  script_name(english:"GLSA-200602-03 : Apache: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200602-03
(Apache: Multiple vulnerabilities)

    Apache's mod_imap fails to properly sanitize the 'Referer' directive of
    imagemaps in some cases, leaving the HTTP Referer header unescaped. A
    flaw in mod_ssl can lead to a NULL pointer dereference if the site uses
    a custom 'Error 400' document. These vulnerabilities were reported by
    Marc Cox and Hartmut Keil, respectively.
  
Impact :

    A remote attacker could exploit mod_imap to inject arbitrary HTML or
    JavaScript into a user's browser to gather sensitive information.
    Attackers could also cause a Denial of Service on hosts using the SSL
    module (Apache 2.0.x only).
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200602-03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Apache users should upgrade to the latest version, depending on
    whether they still use the old configuration style
    (/etc/apache/conf/*.conf) or the new one (/etc/apache2/httpd.conf).
    2.0.x users, new style config:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-servers/apache-2.0.55-r1'
    2.0.x users, old style config:
    # emerge --sync
    # emerge --ask --oneshot --verbose '=www-servers/apache-2.0.54-r16'
    1.x users, new style config:
    # emerge --sync
    # emerge --ask --oneshot --verbose '=www-servers/apache-1.3.34-r11'
    1.x users, old style config:
    # emerge --sync
    # emerge --ask --oneshot --verbose '=www-servers/apache-1.3.34-r2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:apache");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-servers/apache", unaffected:make_list("ge 2.0.55-r1", "rge 2.0.54-r16", "eq 1.3.34-r2", "rge 1.3.34-r11", "rge 1.3.37"), vulnerable:make_list("lt 2.0.55-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Apache");
}
