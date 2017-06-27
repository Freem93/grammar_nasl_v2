#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-10255.
#

include("compat.inc");

if (description)
{
  script_id(67276);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/19 21:02:56 $");

  script_bugtraq_id(60411);
  script_xref(name:"FEDORA", value:"2013-10255");

  script_name(english:"Fedora 18 : php-5.4.16-1.fc18 (2013-10255)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"06 Jun 2013, PHP 5.4.16

Core :

  - Fixed bug #64879 (Heap based buffer overflow in
    quoted_printable_encode, CVE-2013-2110). (Stas)

    - Fixed bug #64853 (Use of no longer available ini
      directives causes crash on TS build). (Anatol)

    - Fixed bug #64729 (compilation failure on x32).
      (Gustavo)

    - Fixed bug #64720 (SegFault on zend_deactivate).
      (Dmitry)

    - Fixed bug #64660 (Segfault on memory exhaustion within
      function definition). (Stas, reported by Juha
      Kylmanen)

Calendar: -Fixed bug #64895 (Integer overflow in SndToJewish). (Remi)

Fileinfo :

  - Fixed bug #64830 (mimetype detection segfaults on mp3
    file). (Anatol)

FPM :

  - Ignore QUERY_STRING when sent in SCRIPT_FILENAME. (Remi)

    - Fixed some possible memory or resource leaks and
      possible null dereference detected by code coverity
      scan. (Remi)

    - Log a warning when a syscall fails. (Remi)

    - Add --with-fpm-systemd option to report health to
      systemd, and systemd_interval option to configure
      this. The service can now use Type=notify in the
      systemd unit file. (Remi)

MySQLi

  - Fixed bug #64726 (Segfault when calling fetch_object on
    a use_result and DB pointer has closed). (Laruence)

Phar

  - Fixed bug #64214 (PHAR PHPTs intermittently crash when
    run on DFS, SMB or with non std tmp dir). (Pierre)

SNMP :

  - Fixed bug #64765 (Some IPv6 addresses get interpreted
    wrong). (Boris Lytochkin)

    - Fixed bug #64159 (Truncated snmpget). (Boris
      Lytochkin)

Streams :

  - Fixed bug #64770 (stream_select() fails with pipes
    returned by proc_open() on Windows x64). (Anatol)

Zend Engine :

  - Fixed bug #64821 (Custom Exceptions crash when internal
    properties overridden). (Anatol)

Fix backported from PHP 5.4.17

Core :

  - Fixed bug #64960 (Segfault in gc_zval_possible_root).
    (Laruence)

FPM :

  - Fixed Bug #64915 (error_log ignored when daemonize=0).
    (Remi)

PDO_pgsql :

  - Fixed Bug #64949 (Buffer overflow in _pdo_pgsql_error).
    (Remi)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109594.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e217726"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/07");
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
if (! ereg(pattern:"^18([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 18.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC18", reference:"php-5.4.16-1.fc18")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");
}
