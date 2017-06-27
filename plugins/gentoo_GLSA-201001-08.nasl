#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201001-08.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(44897);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2009-1381", "CVE-2009-1578", "CVE-2009-1579", "CVE-2009-1580", "CVE-2009-1581");
  script_osvdb_id(54504, 54505, 54506, 54507, 54508);
  script_xref(name:"GLSA", value:"201001-08");

  script_name(english:"GLSA-201001-08 : SquirrelMail: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201001-08
(SquirrelMail: Multiple vulnerabilities)

    Multiple vulnerabilities were found in SquirrelMail:
    Niels
    Teusink reported multiple input sanitation flaws in certain encrypted
    strings in e-mail headers, related to contrib/decrypt_headers.php,
    PHP_SELF and the query string (aka QUERY_STRING) (CVE-2009-1578).
    Niels Teusink also reported that the map_yp_alias() function
    in functions/imap_general.php does not filter shell metacharacters in a
    username and that the original patch was incomplete (CVE-2009-1381,
    CVE-2009-1579).
    Tomas Hoger discovered an unspecified session fixation
    vulnerability (CVE-2009-1580).
    Luc Beurton reported that functions/mime.php does not protect
    the application's content from Cascading Style Sheets (CSS) positioning
    in HTML e-mail messages (CVE-2009-1581).
  
Impact :

    The vulnerabilities allow remote attackers to execute arbitrary code
    with the privileges of the user running the web server, to hijack web
    sessions via a crafted cookie, to spoof the user interface and to
    conduct Cross-Site Scripting and phishing attacks, via a specially
    crafted message.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201001-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All SquirrelMail users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-client/squirrelmail-1.4.19'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(79, 94, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:squirrelmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"mail-client/squirrelmail", unaffected:make_list("ge 1.4.19"), vulnerable:make_list("lt 1.4.19"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "SquirrelMail");
}
