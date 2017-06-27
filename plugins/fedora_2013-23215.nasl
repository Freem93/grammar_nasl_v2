#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-23215.
#

include("compat.inc");

if (description)
{
  script_id(71552);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/19 21:47:14 $");

  script_cve_id("CVE-2013-6420");
  script_xref(name:"FEDORA", value:"2013-23215");

  script_name(english:"Fedora 18 : php-5.4.23-1.fc18 (2013-23215)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"28 Nov 2013, PHP 5.4.23

Core :

  - Fixed bug #66094 (unregister_tick_function tries to cast
    a Closure to a string). (Laruence)

    - Fixed bug #65947 (basename is no more working after
      fgetcsv in certain situation). (Laruence)

JSON

  - Fixed whitespace part of bug #64874 ('json_decode
    handles whitespace and case-sensitivity incorrectly').
    (Andrea Faulds)

MySQLi :

  - Fixed bug #66043 (Segfault calling bind_param() on
    mysqli). (Laruence)

mysqlnd :

  - Fixed bug #66124 (mysqli under mysqlnd loses precision
    when bind_param with 'i'). (Andrey)

    - Fixed bug #66141 (mysqlnd quote function is wrong with
      NO_BACKSLASH_ESCAPES after failed query). (Andrey)

OpenSSL :

  - Fixed memory corruption in openssl_x509_parse()
    (CVE-2013-6420). (Stefan Esser).

PDO

  - Fixed bug 65946 (sql_parser permanently converts values
    bound to strings)

Backported from 5.5.8

  - fix zend_register_functions breaks reflection, php bug
    66218

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1036830"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/124713.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3b58a4d9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^18([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 18.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC18", reference:"php-5.4.23-1.fc18")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");
}
