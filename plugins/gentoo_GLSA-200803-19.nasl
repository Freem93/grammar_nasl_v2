#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200803-19.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(31445);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2007-6203", "CVE-2007-6422", "CVE-2008-0005", "CVE-2008-0455", "CVE-2008-0456");
  script_osvdb_id(39003, 40264, 41018, 41019, 42214);
  script_xref(name:"GLSA", value:"200803-19");

  script_name(english:"GLSA-200803-19 : Apache: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200803-19
(Apache: Multiple vulnerabilities)

    Adrian Pastor and Amir Azam (ProCheckUp) reported that the HTTP Method
    specifier header is not properly sanitized when the HTTP return code is
    '413 Request Entity too large' (CVE-2007-6203). The mod_proxy_balancer
    module does not properly check the balancer name before using it
    (CVE-2007-6422). The mod_proxy_ftp does not define a charset in its
    answers (CVE-2008-0005). Stefano Di Paola (Minded Security) reported
    that filenames are not properly sanitized within the mod_negotiation
    module (CVE-2008-0455, CVE-2008-0456).
  
Impact :

    A remote attacker could entice a user to visit a malicious URL or send
    specially crafted HTTP requests (i.e using Adobe Flash) to perform
    Cross-Site Scripting and HTTP response splitting attacks, or conduct a
    Denial of Service attack on the vulnerable web server.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200803-19"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Apache users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-servers/apache-2.2.8'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 94, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:apache");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/11/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-servers/apache", unaffected:make_list("ge 2.2.8"), vulnerable:make_list("lt 2.2.8"))) flag++;

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
