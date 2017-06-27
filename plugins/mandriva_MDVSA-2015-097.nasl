#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:097. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(82350);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/30 13:59:00 $");

  script_cve_id("CVE-2014-2681", "CVE-2014-2682", "CVE-2014-2683", "CVE-2014-2684", "CVE-2014-2685", "CVE-2014-4914", "CVE-2014-8088", "CVE-2014-8089");
  script_xref(name:"MDVSA", value:"2015:097");

  script_name(english:"Mandriva Linux Security Advisory : php-ZendFramework (MDVSA-2015:097)");
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
"Updated php-ZendFramework packages fix multiple vulnerabilities :

XML eXternal Entity (XXE) and XML Entity Expansion (XEE) flaws were
discovered in the Zend Framework. An attacker could use these flaws to
cause a denial of service, access files accessible to the server
process, or possibly perform other more advanced XML External Entity
(XXE) attacks (CVE-2014-2681, CVE-2014-2682, CVE-2014-2683).

Using the Consumer component of Zend_OpenId, it is possible to login
using an arbitrary OpenID account (without knowing any secret
information) by using a malicious OpenID Provider. That means OpenID
it is possible to login using arbitrary OpenID Identity (MyOpenID,
Google, etc), which are not under the control of our own OpenID
Provider. Thus, we are able to impersonate any OpenID Identity against
the framework (CVE-2014-2684, CVE-2014-2685).

The implementation of the ORDER BY SQL statement in Zend_Db_Select of
Zend Framework 1 contains a potential SQL injection when the query
string passed contains parentheses (CVE-2014-4914).

Due to a bug in PHP's LDAP extension, when ZendFramework's Zend_ldap
class is used for logins, an attacker can login as any user by using a
null byte to bypass the empty password check and perform an
unauthenticated LDAP bind (CVE-2014-8088).

The sqlsrv PHP extension, which provides the ability to connect to
Microsoft SQL Server from PHP, does not provide a built-in quoting
mechanism for manually quoting values to pass via SQL queries;
developers are encouraged to use prepared statements. Zend Framework
provides quoting mechanisms via Zend_Db_Adapter_Sqlsrv which uses the
recommended double single quote ('') as quoting delimiters. SQL Server
treats null bytes in a query as a string terminator, allowing an
attacker to add arbitrary SQL following a null byte, and thus create a
SQL injection (CVE-2014-8089)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0151.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0311.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0434.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ZendFramework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ZendFramework-Cache-Backend-Apc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ZendFramework-Cache-Backend-Memcached");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ZendFramework-Captcha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ZendFramework-Dojo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ZendFramework-Feed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ZendFramework-Gdata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ZendFramework-Pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ZendFramework-Search-Lucene");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ZendFramework-Services");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ZendFramework-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ZendFramework-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ZendFramework-tests");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS2", reference:"php-ZendFramework-1.12.9-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"php-ZendFramework-Cache-Backend-Apc-1.12.9-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"php-ZendFramework-Cache-Backend-Memcached-1.12.9-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"php-ZendFramework-Captcha-1.12.9-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"php-ZendFramework-Dojo-1.12.9-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"php-ZendFramework-Feed-1.12.9-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"php-ZendFramework-Gdata-1.12.9-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"php-ZendFramework-Pdf-1.12.9-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"php-ZendFramework-Search-Lucene-1.12.9-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"php-ZendFramework-Services-1.12.9-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"php-ZendFramework-demos-1.12.9-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"php-ZendFramework-extras-1.12.9-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"php-ZendFramework-tests-1.12.9-1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
