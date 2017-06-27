#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200405-16.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14502);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/10/05 13:32:57 $");

  script_cve_id("CVE-2004-0519", "CVE-2004-0521");
  script_bugtraq_id(10246);
  script_osvdb_id(6841);
  script_xref(name:"CERT-CC", value:"CA-2000-02");
  script_xref(name:"GLSA", value:"200405-16");

  script_name(english:"GLSA-200405-16 : Multiple XSS Vulnerabilities in SquirrelMail");
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
"The remote host is affected by the vulnerability described in GLSA-200405-16
(Multiple XSS Vulnerabilities in SquirrelMail)

    Several unspecified cross-site scripting (XSS) vulnerabilities and a
    well-hidden SQL injection vulnerability were found. An XSS attack
    allows an attacker to insert malicious code into a web-based
    application. SquirrelMail does not check for code when parsing
    variables received via the URL query string.
  
Impact :

    One of the XSS vulnerabilities could be exploited by an attacker to
    steal cookie-based authentication credentials from the user's browser.
    The SQL injection issue could potentially be used by an attacker to run
    arbitrary SQL commands inside the SquirrelMail database with privileges
    of the SquirrelMail database user.
  
Workaround :

    There is no known workaround at this time. All users are advised to
    upgrade to version 1.4.3_rc1 or higher of SquirrelMail."
  );
  # http://sourceforge.net/mailarchive/forum.php?thread_id=4199060&forum_id=1988
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?df1d7e3b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200405-16"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All SquirrelMail users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv '>=mail-client/squirrelmail-1.4.3_rc1'
    # emerge '>=mail-client/squirrelmail-1.4.3_rc1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:squirrelmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/27");
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

if (qpkg_check(package:"mail-client/squirrelmail", unaffected:make_list("ge 1.4.3_rc1"), vulnerable:make_list("lt 1.4.3_rc1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mail-client/squirrelmail");
}
