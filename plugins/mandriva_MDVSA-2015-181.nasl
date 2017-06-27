#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:181. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(82456);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/28 21:52:55 $");

  script_cve_id("CVE-2014-2983", "CVE-2014-3704", "CVE-2014-5019", "CVE-2014-5020", "CVE-2014-5021", "CVE-2014-5022", "CVE-2014-9015", "CVE-2014-9016", "CVE-2015-2559", "CVE-2015-2749", "CVE-2015-2750");
  script_xref(name:"MDVSA", value:"2015:181");

  script_name(english:"Mandriva Linux Security Advisory : drupal (MDVSA-2015:181)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated drupal packages fix security vulnerabilities :

An information disclosure vulnerability was discovered in Drupal
before 7.27. When pages are cached for anonymous users, form state may
leak between anonymous users. Sensitive or private information
recorded for one anonymous user could thus be disclosed to other users
interacting with the same form at the same time (CVE-2014-2983).

Multiple security issues in Drupal before 7.29, including a denial of
service issue, an access bypass issue in the File module, and multiple
cross-site scripting issues (CVE-2014-5019, CVE-2014-5020,
CVE-2014-5021, CVE-2014-5022).

A denial of service issue exists in Drupal before 7.31, due to XML
entity expansion in a publicly accessible XML-RPC endpoint.

A SQL Injection issue exists in Drupal before 7.32 due to the way the
Drupal core handles prepared statements. A malicious user can inject
arbitrary SQL queries, and thereby completely control the Drupal site.
This vulnerability can be exploited by remote attackers without any
kind of authentication required (CVE-2014-3704).

Aaron Averill discovered that a specially crafted request can give a
user access to another user's session, allowing an attacker to hijack
a random session (CVE-2014-9015).

Michael Cullum, Javier Nieto and Andres Rojas Guerrero discovered that
the password hashing API allows an attacker to send specially crafted
requests resulting in CPU and memory exhaustion. This may lead to the
site becoming unavailable or unresponsive (denial of service)
(CVE-2014-9016). anonymous users (CVE-2014-9016).

Password reset URLs can be forged under certain circumstances,
allowing an attacker to gain access to another user's account without
knowing the account's password (CVE-2015-2559).

Under certain circumstances, malicious users can construct a URL that
will trick users into being redirected to a 3rd party website, thereby
exposing the users to potential social engineering attacks. In
addition, several URL-related API functions in Drupal 6 and 7 can be
tricked into passing through external URLs when not intending to,
potentially leading to additional open redirect vulnerabilities
(CVE-2015-2749, CVE-2015-2750).

The drupal package has been updated to version 7.35 to fix this issue
and other bugs. See the upstream advisory and release notes for more
details."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0322.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0329.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0423.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0492.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2015-0121.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Drupal core 7.x SQL Injection");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Drupal HTTP Parameter Key/Value SQL Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:drupal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:drupal-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:drupal-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:drupal-sqlite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS1", reference:"drupal-7.35-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"drupal-mysql-7.35-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"drupal-postgresql-7.35-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"drupal-sqlite-7.35-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
