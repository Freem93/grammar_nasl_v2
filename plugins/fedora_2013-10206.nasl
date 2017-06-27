#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-10206.
#

include("compat.inc");

if (description)
{
  script_id(67273);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/19 21:02:56 $");

  script_xref(name:"FEDORA", value:"2013-10206");

  script_name(english:"Fedora 19 : php-5.5.0-0.10.RC3.fc19 / php-pecl-jsonc-1.3.1-1.fc19 (2013-10206)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IMPORTANT CHANGE :

  - JSON extension is no more provided by php-common

    - php-pecl-jsonc provides a drop-in alternative

Upstream Changelog, 06 Jun 2013, PHP 5.5.0 Release Candidate 3

Core :

  - Fixed bug #64960 (Segfault in gc_zval_possible_root).
    (Laruence)

    - Fixed bug #64879 (Heap based buffer overflow in
      quoted_printable_encode, CVE-2013-2110). (Stas)

FPM :

  - Fixed Bug #64915 (error_log ignored when daemonize=0).
    (Remi)

GD :

  - Fixed Bug #64962 (imagerotate produces corrupted image).
    (Remi)

    - Fixed Bug #64961 (segfault in imagesetinterpolation).
      (Remi)

Hash :

  - Fixed Bug #64745 (hash_pbkdf2() truncates data when
    using default length and hex output). (Anthony Ferrara)

PDO_DBlib :

  - Fixed bug #63638 (Cannot connect to SQL Server 2008 with
    PDO dblib). (Stanley Sufficool)

    - Fixed bug #64338 (pdo_dblib can't connect to Azure
      SQL). (Stanley Sufficool)

    - Fixed bug #64808 (FreeTDS PDO getColumnMeta on a
      prepared but not executed statement crashes). (Stanley
      Sufficool)

PDO_pgsql :

  - Fixed Bug #64949 (Buffer overflow in _pdo_pgsql_error).
    (Remi)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=973696"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109515.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3166a1df"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109516.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?11906567"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php and / or php-pecl-jsonc packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-pecl-jsonc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:19");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
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
if (! ereg(pattern:"^19([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 19.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC19", reference:"php-5.5.0-0.10.RC3.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"php-pecl-jsonc-1.3.1-1.fc19")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-pecl-jsonc");
}
