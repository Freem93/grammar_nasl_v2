#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-deb2bbdde0.
#

include("compat.inc");

if (description)
{
  script_id(89437);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/03/04 16:10:31 $");

  script_xref(name:"FEDORA", value:"2015-deb2bbdde0");

  script_name(english:"Fedora 23 : phpMyAdmin-4.5.3.1-1.fc23 (2015-deb2bbdde0)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"phpMyAdmin 4.5.3.1 (2015-12-25) =============================== -
Undefined offset 2 - [Security] Path disclosure, see PMASA-2015-6 ----
phpMyAdmin 4.5.3.0 (2015-12-23) =============================== -
Incomplete results of UNION ALL - MATCH AGAINST keywords not
recognized - syntax verifier is not knowing 'STRAIGHT_JOIN' -
REPLACE() function confused with REPLACE statement - FLUSH word not
recognized by parser - Online syntax verifier bug - 'IF' on SELECT
statement - Format breaks query with COUNT() - Undefinex index:
SendErrorReports - Incorrect script name in include - Warning: Invalid
argument supplied for foreach() - Delimiter missing while exporting
multiple db routines

  - mysql_native_password with MariaDB bug - Flush
    privileges overusage - related to #11597 - Query was
    empty on creating User in 4.5.2 -
    PMA_getDataForDeleteUsers() warning - Cannot create user
    on Percona Server - Properly report error on connecting
    - Database export template not saving compression option
    - Fix single quote export for servers in ANSI_QUOTES
    mode - Avoid duplicite fetching of table information -
    Temporary fix for live data edit of big sets is not
    working - IE 8 compatibility in console - Exporting
    feature does not work with union table - CSV import skip
    row count after - Cannot export results of some queries
    - Message 'An account already exists...' incorrectly
    displayed - Missing quoting of table in ALTER CONVERT
    query - PMA 4.5.2 breaks MySQL Master-Master Cluster -
    Export and preview show different SQL for character set
    - Fix possible undefined variables in table operations

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1294254"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-December/174721.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a307c6aa"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpMyAdmin package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:23");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^23([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 23.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC23", reference:"phpMyAdmin-4.5.3.1-1.fc23")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phpMyAdmin");
}
