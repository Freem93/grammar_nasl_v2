#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-12315.
#

include("compat.inc");

if (description)
{
  script_id(69000);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/19 21:02:57 $");

  script_cve_id("CVE-2013-4113");
  script_bugtraq_id(61128);
  script_xref(name:"FEDORA", value:"2013-12315");

  script_name(english:"Fedora 18 : php-5.4.17-2.fc18 (2013-12315)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"04 Jul 2013, PHP 5.4.17

Core :

  - Fixed bug #64988 (Class loading order affects E_STRICT
    warning). (Laruence)

    - Fixed bug #64966 (segfault in
      zend_do_fcall_common_helper_SPEC). (Laruence)

    - Fixed bug #64960 (Segfault in gc_zval_possible_root).
      (Laruence)

    - Fixed bug #64936 (doc comments picked up from previous
      scanner run). (Stas, Jonathan Oddy)

    - Fixed bug #64934 (Apache2 TS crash with
      get_browser()). (Anatol)

    - Fixed bug #64166 (quoted-printable-encode stream
      filter incorrectly discarding whitespace). (Michael M
      Slusarz)

DateTime :

  - Fixed bug #53437 (Crash when using unserialized
    DatePeriod instance). (Gustavo, Derick, Anatol)

FPM :

  - Fixed Bug #64915 (error_log ignored when daemonize=0).
    (Remi)

    - Implemented FR #64764 (add support for FPM init.d
      script). (Lior Kaplan)

PDO :

  - Fixed bug #63176 (Segmentation fault when instantiate 2
    persistent PDO to the same db server). (Laruence)

PDO_DBlib :

  - Fixed bug #63638 (Cannot connect to SQL Server 2008 with
    PDO dblib). (Stanley Sufficool)

    - Fixed bug #64338 (pdo_dblib can't connect to Azure
      SQL). (Stanley Sufficool)

    - Fixed bug #64808 (FreeTDS PDO getColumnMeta on a
      prepared but not executed statement crashes). (Stanley
      Sufficool)

PDO_firebird :

  - Fixed bug #64037 (Firebird return wrong value for
    numeric field). (Matheus Degiovani, Matteo)

    - Fixed bug #62024 (Cannot insert second row with null
      using parametrized query). (patch by james at
      kenjim.com, Matheus Degiovani, Matteo)

PDO_mysql :

  - Fixed bug #48724 (getColumnMeta() doesn't return
    native_type for BIT, TINYINT and YEAR). (Antony, Daniel
    Beardsley)

PDO_pgsql :

  - Fixed Bug #64949 (Buffer overflow in _pdo_pgsql_error).
    (Remi)

pgsql :

  - Fixed bug #64609 (pg_convert enum type support).
    (Matteo)

Readline :

  - Implement FR #55694 (Expose additional readline variable
    to prevent default filename completion). (Hartmel)

SPL :

  - Fixed bug #64997 (Segfault while using
    RecursiveIteratorIterator on 64-bits systems).
    (Laruence)

Backported from 5.4.18

CGI :

  - Fixed Bug #65143 (Missing php-cgi man page). (Remi)

Phar :

  - Fixed Bug #65142 (Missing phar man page). (Remi)

XML :

  - Fixed bug #65236 (heap corruption in xml parser).
    CVE-2013-4113

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=983689"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112237.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a91adb17"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/23");
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
if (rpm_check(release:"FC18", reference:"php-5.4.17-2.fc18")) flag++;


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
