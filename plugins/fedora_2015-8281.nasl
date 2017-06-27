#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-8281.
#

include("compat.inc");

if (description)
{
  script_id(83835);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2015/10/19 23:14:53 $");

  script_cve_id("CVE-2006-7243", "CVE-2015-4021", "CVE-2015-4022", "CVE-2015-4024", "CVE-2015-4025", "CVE-2015-4026");
  script_xref(name:"FEDORA", value:"2015-8281");

  script_name(english:"Fedora 22 : php-5.6.9-1.fc22 (2015-8281)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"14 May 2015, **PHP 5.6.9**

Core :

  - Fixed bug #69467 (Wrong checked for the interface by
    using Trait). (Laruence)

    - Fixed bug #69420 (Invalid read in
      zend_std_get_method). (Laruence)

    - Fixed bug #60022 ('use statement [...] has no effect'
      depends on leading backslash). (Nikita)

    - Fixed bug #67314 (Segmentation fault in
      gc_remove_zval_from_buffer). (Dmitry)

    - Fixed bug #68652 (segmentation fault in destructor).
      (Dmitry)

    - Fixed bug #69419 (Returning compatible sub generator
      produces a warning). (Nikita)

    - Fixed bug #69472 (php_sys_readlink ignores misc errors
      from GetFinalPathNameByHandleA). (Jan Starke)

    - Fixed bug #69364 (PHP Multipart/form-data remote dos
      Vulnerability). (Stas)

    - Fixed bug #69403 (str_repeat() sign mismatch based
      memory corruption). (Stas)

    - Fixed bug #69418 (CVE-2006-7243 fix regressions in
      5.4+). (Stas)

    - Fixed bug #69522 (heap buffer overflow in unpack()).
      (Stas)

FTP :

  - Fixed bug #69545 (Integer overflow in ftp_genlist()
    resulting in heap overflow). (Stas)

ODBC :

  - Fixed bug #69354 (Incorrect use of SQLColAttributes with
    ODBC 3.0). (Anatol)

    - Fixed bug #69474 (ODBC: Query with same field name
      from two tables returns incorrect result). (Anatol)

    - Fixed bug #69381 (out of memory with sage odbc
      driver). (Frederic Marchall, Anatol Belski)

OpenSSL :

  - Fixed bug #69402 (Reading empty SSL stream hangs until
    timeout). (Daniel Lowrey)

PCNTL :

  - Fixed bug #68598 (pcntl_exec() should not allow null
    char). (Stas)

PCRE :

  - Upgraded pcrelib to 8.37.

Phar :

  - Fixed bug #69453 (Memory Corruption in
    phar_parse_tarfile when entry filename starts with
    null). (Stas)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1222485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1223408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1223412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1223422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1223425"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-May/158616.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe99a38e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/27");
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
if (rpm_check(release:"FC22", reference:"php-5.6.9-1.fc22")) flag++;


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
