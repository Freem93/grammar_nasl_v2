#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-2315.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(81459);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/19 23:06:17 $");

  script_xref(name:"FEDORA", value:"2015-2315");

  script_name(english:"Fedora 21 : php-5.6.6-1.fc21 (2015-2315)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"19 Feb 2015, PHP 5.6.6

Core :

  - Removed support for multi-line headers, as the are
    deprecated by RFC 7230. (Stas)

    - Fixed bug #67068 (getClosure returns somethings that's
      not a closure). (Danack at basereality dot com)

    - Fixed bug #68942 (Use after free vulnerability in
      unserialize() with DateTimeZone). (CVE-2015-0273)
      (Stas)

    - Fixed bug #68925 (Mitigation for CVE-2015-0235 '
      GHOST: glibc gethostbyname buffer overflow). (Stas)

    - Fixed Bug #67988 (htmlspecialchars() does not respect
      default_charset specified by ini_set) (Yasuo)

    - Added NULL byte protection to exec, system and
      passthru. (Yasuo)

Dba :

  - Fixed bug #68711 (useless comparisons). (bugreports at
    internot dot info)

Enchant :

  - Fixed bug #68552 (heap buffer overflow in
    enchant_broker_request_dict()). (Antony)

Fileinfo :

  - Fixed bug #68827 (Double free with disabled ZMM).
    (Joshua Rogers)

    - Fixed bug #67647 (Bundled libmagic 5.17 does not
      detect quicktime files correctly). (Anatol)

    - Fixed bug #68731 (finfo_buffer doesn't extract the
      correct mime with some gifs). (Anatol)

FPM :

  - Fixed bug #66479 (Wrong response to FCGI_GET_VALUES).
    (Frank Stolle)

    - Fixed bug #68571 (core dump when webserver close the
      socket). (redfoxli069 at gmail dot com, Laruence)

LIBXML :

  - Fixed bug #64938 (libxml_disable_entity_loader setting
    is shared between threads). (Martin Jansen)

Mysqli :

  - Fixed bug #68114 (linker error on some OS X machines
    with fixed width decimal support) (Keyur Govande)

    - Fixed bug #68657 (Reading 4 byte floats with Mysqli
      and libmysqlclient has rounding errors) (Keyur
      Govande)

Opcache :

  - Fixed bug with try blocks being removed when
    extended_info opcode generation is turned on. (Laruence)

PDO_mysql :

  - Fixed bug #68750 (PDOMysql with mysqlnd does not allow
    the usage of named pipes). (steffenb198 at aol dot com)

Phar :

  - Fixed bug #68901 (use after free). (bugreports at
    internot dot info)

Pgsql :

  - Fixed Bug #65199 (pg_copy_from() modifies input array
    variable) (Yasuo)

Session :

  - Fixed bug #68941 (mod_files.sh is a bash-script)
    (bugzilla at ii.nl, Yasuo)

    - Fixed Bug #66623 (no EINTR check on flock) (Yasuo)

    - Fixed bug #68063 (Empty session IDs do still start
      sessions) (Yasuo)

Sqlite3 :

  - Fixed bug #68260 (SQLite3Result::fetchArray declares
    wrong required_num_args). (Julien)

Standard :

  - Fixed bug #65272 (flock() out parameter not set
    correctly in windows). (Daniel Lowrey)

    - Fixed bug #69033 (Request may get env. variables from
      previous requests if PHP works as FastCGI). (Anatol)

Streams :

  - Fixed bug which caused call after final close on streams
    filter. (Bob)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-February/150370.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f7e0c26f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:21");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/24");
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
if (! ereg(pattern:"^21([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 21.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC21", reference:"php-5.6.6-1.fc21")) flag++;


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
