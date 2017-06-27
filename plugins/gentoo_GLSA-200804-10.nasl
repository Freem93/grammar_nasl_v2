#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200804-10.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(31957);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2007-5333", "CVE-2007-5342", "CVE-2007-5461", "CVE-2007-6286", "CVE-2008-0002");
  script_osvdb_id(38187, 39833, 41434, 41435, 41436, 48610);
  script_xref(name:"GLSA", value:"200804-10");

  script_name(english:"GLSA-200804-10 : Tomcat: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200804-10
(Tomcat: Multiple vulnerabilities)

    The following vulnerabilities were reported:
    Delian Krustev discovered that the JULI logging component does not
    properly enforce access restrictions, allowing web application to add
    or overwrite files (CVE-2007-5342).
    When the native APR connector is used, Tomcat does not properly handle
    an empty request to the SSL port, which allows remote attackers to
    trigger handling of a duplicate copy of one of the recent requests
    (CVE-2007-6286).
    If the processing or parameters is interrupted, i.e. by an exception,
    then it is possible for the parameters to be processed as part of later
    request (CVE-2008-0002).
    An absolute path traversal vulnerability exists due to the way that
    WebDAV write requests are handled (CVE-2007-5461).
    Tomcat does not properly handle double quote (') characters or %5C
    (encoded backslash) sequences in a cookie value, which might cause
    sensitive information such as session IDs to be leaked to remote
    attackers and enable session hijacking attacks
    (CVE-2007-5333).
  
Impact :

    These vulnerabilities can be exploited by:
    a malicious web application to add or overwrite files with the
    permissions of the user running Tomcat.
    a remote attacker to conduct session hijacking or disclose sensitive
    data.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200804-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Tomcat 5.5.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-servers/tomcat-5.5.26'
    All Tomcat 6.0.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-servers/tomcat-6.0.16'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cwe_id(22, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:tomcat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/17");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/14");
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

if (qpkg_check(package:"www-servers/tomcat", unaffected:make_list("rge 5.5.26", "ge 6.0.16", "rge 5.5.27"), vulnerable:make_list("lt 6.0.16"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Tomcat");
}
