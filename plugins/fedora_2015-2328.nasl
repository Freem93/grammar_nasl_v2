#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-2328.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(81612);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/20 14:02:59 $");

  script_bugtraq_id(64225, 67118, 72325, 72701);
  script_xref(name:"FEDORA", value:"2015-2328");

  script_name(english:"Fedora 20 : php-5.5.22-1.fc20 (2015-2328)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"19 Feb 2015, PHP 5.5.22

Core :

  - Fixed bug #67068 (getClosure returns somethings that's
    not a closure). (Danack at basereality dot com)

    - Fixed bug #68925 (Mitigation for CVE-2015-0235 '
      GHOST: glibc gethostbyname buffer overflow). (Stas)

    - Fixed bug #68942 (Use after free vulnerability in
      unserialize() with DateTimeZone). (CVE-2015-0273)
      (Stas)

    - Added NULL byte protection to exec, system and
      passthru. (Yasuo)

    - Removed support for multi-line headers, as the are
      deprecated by RFC 7230. (Stas)

Date :

  - Fixed bug #45081 (strtotime incorrectly interprets SGT
    time zone). (Derick)

Dba :

  - Fixed bug #68711 (useless comparisons). (bugreports at
    internot dot info)

Enchant :

  - Fixed bug #6855 (heap buffer overflow in
    enchant_broker_request_dict()). (Antony)

Fileinfo :

  - Fixed bug #68827 (Double free with disabled ZMM).
    (Joshua Rogers)

FPM :

  - Fixed bug #66479 (Wrong response to FCGI_GET_VALUES).
    (Frank Stolle)

    - Fixed bug #68571 (core dump when webserver close the
      socket). (redfoxli069 at gmail dot com, Laruence)

Libxml :

  - Fixed bug #64938 (libxml_disable_entity_loader setting
    is shared between threads). (Martin Jansen)

OpenSSL :

  - Fixed bug #55618 (use case-insensitive cert name
    matching). (Daniel Lowrey)

PDO_mysql :

  - Fixed bug #68750 (PDOMysql with mysqlnd does not allow
    the usage of named pipes). (steffenb198 at aol.com)

Phar :

  - Fixed bug #68901 (use after free). (bugreports at
    internot dot info)

Pgsql :

  - Fixed Bug #65199 'pg_copy_from() modifies input array
    variable). (Yasuo)

Sqlite3 :

  - Fixed bug #68260 (SQLite3Result::fetchArray declares
    wrong required_num_args). (Julien)

Mysqli :

  - Fixed bug #68114 (linker error on some OS X machines
    with fixed width decimal support) (Keyur Govande)

    - Fixed bug #68657 (Reading 4 byte floats with Mysqli
      and libmysqlclient has rounding errors) (Keyur
      Govande)

Session :

  - Fixed bug #68941 (mod_files.sh is a bash-script)
    (bugzilla at ii.nl, Yasuo)

    - Fixed Bug #66623 (no EINTR check on flock) (Yasuo)

    - Fixed bug #68063 (Empty session IDs do still start
      sessions) (Yasuo)

Standard :

  - Fixed bug #65272 (flock() out parameter not set
    correctly in windows). (Daniel Lowrey)

    - Fixed bug #69033 (Request may get env. variables from
      previous requests if PHP works as FastCGI)

Streams :

  - Fixed bug which caused call after final close on streams
    filter. (Bob)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-March/150624.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c7c73c8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim GHOST (glibc gethostbyname) Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/05");
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
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"php-5.5.22-1.fc20")) flag++;


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
