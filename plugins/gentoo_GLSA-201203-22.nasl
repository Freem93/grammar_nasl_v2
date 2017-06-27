#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201203-22.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(59614);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2009-3555", "CVE-2009-3896", "CVE-2009-3898", "CVE-2011-4315", "CVE-2012-1180");
  script_bugtraq_id(36490, 36839, 36935, 50710, 52578);
  script_osvdb_id(58328, 59278, 77184, 80124);
  script_xref(name:"GLSA", value:"201203-22");

  script_name(english:"GLSA-201203-22 : nginx: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201203-22
(nginx: Multiple vulnerabilities)

    Multiple vulnerabilities have been found in nginx:
      The TLS protocol does not properly handle session renegotiation
        requests (CVE-2009-3555).
      The 'ngx_http_process_request_headers()' function in ngx_http_parse.c
        could cause a NULL pointer dereference (CVE-2009-3896).
      nginx does not properly sanitize user input for the the WebDAV COPY
        or MOVE methods (CVE-2009-3898).
      The 'ngx_resolver_copy()' function in ngx_resolver.c contains a
        boundary error which could cause a heap-based buffer overflow
        (CVE-2011-4315).
      nginx does not properly parse HTTP header responses which could
        expose sensitive information (CVE-2012-1180).
  
Impact :

    A remote attacker could possibly execute arbitrary code with the
      privileges of the nginx process, cause a Denial of Service condition,
      create or overwrite arbitrary files, or obtain sensitive information.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201203-22"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All nginx users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-servers/nginx-1.0.14'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 119, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:nginx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-servers/nginx", unaffected:make_list("ge 1.0.14"), vulnerable:make_list("lt 1.0.14"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nginx");
}
