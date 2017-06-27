#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-11581.
#

include("compat.inc");

if (description)
{
  script_id(85061);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/10/18 16:42:52 $");

  script_cve_id("CVE-2015-5589", "CVE-2015-5590");
  script_xref(name:"FEDORA", value:"2015-11581");

  script_name(english:"Fedora 21 : php-5.6.11-1.fc21 (2015-11581)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"10 Jul 2015, **PHP 5.6.11**

**Core:**

  - Fixed bug #69768 (escapeshell*() doesn't cater to !).
    (cmb)

    - Fixed bug #69703 (Use __builtin_clzl on PowerPC). (dja
      at axtens dot net, Kalle)

    - Fixed bug #69732 (can induce segmentation fault with
      basic php code). (Dmitry)

    - Fixed bug #69642 (Windows 10 reported as Windows 8).
      (Christian Wenz, Anatol Belski)

    - Fixed bug #69551 (parse_ini_file() and
      parse_ini_string() segmentation fault). (Christoph M.
      Becker)

    - Fixed bug #69781 (phpinfo() reports Professional
      Editions of Windows 7/8/8.1/10 as 'Business').
      (Christian Wenz)

    - Fixed bug #69740 (finally in generator (yield)
      swallows exception in iteration). (Nikita)

    - Fixed bug #69835 (phpinfo() does not report many
      Windows SKUs). (Christian Wenz)

    - Fixed bug #69892 (Different arrays compare indentical
      due to integer key truncation). (Nikita)

    - Fixed bug #69874 (Can't set empty additional_headers
      for mail()), regression from fix to bug #68776.
      (Yasuo)

**GD:**

  - Fixed bug #61221 (imagegammacorrect function loses alpha
    channel). (cmb)

**GMP:**

  - Fixed bug #69803 (gmp_random_range() modifies second
    parameter if GMP number). (Nikita)

**PCRE:**

  - Fixed Bug #53823 (preg_replace: * qualifier on unicode
    replace garbles the string). (cmb)

    - Fixed bug #69864 (Segfault in preg_replace_callback)
      (cmb, ab)

**PDO_pgsql:**

  - Fixed bug #69752 (PDOStatement::execute() leaks memory
    with DML Statements when closeCuror() is u). (Philip
    Hofstetter)

    - Fixed bug #69362 (PDO-pgsql fails to connect if
      password contains a leading single quote). (Matteo)

    - Fixed bug #69344 (PDO PgSQL Incorrect binding numeric
      array with gaps). (Matteo)

**SimpleXML:**

  - Refactored the fix for bug #66084
    (simplexml_load_string() mangles empty node name).
    (Christoph Michael Becker)

**SPL:**

  - Fixed bug #69737 (Segfault when SplMinHeap::compare
    produces fatal error). (Stas)

    - Fixed bug #67805 (SplFileObject setMaxLineLength).
      (Willian Gustavo Veiga).

    - Fixed bug #69970 (Use-after-free vulnerability in
      spl_recursive_it_move_forward_ex()). (Laruence)

**Sqlite3:**

  - Fixed bug #69972 (Use-after-free vulnerability in
    sqlite3SafetyCheckSickOrOk()). (Laruence)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1245236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1245242"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-July/162559.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?12ddc91a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:21");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^21([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 21.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC21", reference:"php-5.6.11-1.fc21")) flag++;


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
