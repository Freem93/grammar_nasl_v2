#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-8704.
#

include("compat.inc");

if (description)
{
  script_id(83932);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/10/19 23:22:34 $");

  script_cve_id("CVE-2015-3154");
  script_xref(name:"FEDORA", value:"2015-8704");

  script_name(english:"Fedora 22 : php-ZendFramework-1.12.13-1.fc22 (2015-8704)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**Zend Framework 1.12.13**

  - 567: Cast int and float to string when creating headers

**Zend Framework 1.12.12**

  - 493: PHPUnit not being installed

    - 511: Add PATCH to the list of allowed methods in
      Zend_Controller_Request_HttpTestCase

    - 513: Save time and space when cloning PHPUnit

    - 515: !IE conditional comments bug

    - 516: Zend_Locale does not honor parentLocale
      configuration

    - 518: Run travis build also on PHP 7 builds

    - 534: Failing unit test:
      Zend_Validate_EmailAddressTest::testIdnHostnameInEmail
      lAddress

    - 536: Zend_Measure_Number convert some decimal numbers
      to roman with space char

    - 537: Extend view renderer controller fix (#440)

    - 540: Fix PHP 7 BC breaks in Zend_XmlRpc/Amf_Server

    - 541: Fixed errors in tests on PHP7

    - 542: Correctly reset the sub-path when processing
      routes

    - 545: Fixed path delimeters being stripped by chain
      routes affecting later routes

    - 546: TravisCI: Skip memcache(d) on PHP 5.2

    - 547: Session Validators throw 'general' Session
      Exception during Session start

    - 550: Notice 'Undefined index: browser_version'

    - 557: doc: Zend Framework Dependencies table unreadable

    - 559: Fixes a typo in Zend_Validate messages for SK

    - 561: Zend_Date not expected year

    - 564: Zend_Application tries to load
      ZendX_Application_Resource_FrontController during
      instantiation

**Security**

  - **ZF2015-04**: Zend_Mail and Zend_Http were both
    susceptible to CRLF Injection Attack vectors (for HTTP,
    this is often referred to as HTTP Response Splitting).
    Both components were updated to perform header value
    validations to ensure no values contain characters not
    detailed in their corresponding specifications, and will
    raise exceptions on detection. Each also provides new
    facilities for both validating and filtering header
    values prior to injecting them into header classes. If
    you use either Zend_Mail or Zend_Http, we recommend
    upgrading immediately.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1215712"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-May/159172.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3b982db5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-ZendFramework package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-ZendFramework");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^22([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 22.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC22", reference:"php-ZendFramework-1.12.13-1.fc22")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-ZendFramework");
}
