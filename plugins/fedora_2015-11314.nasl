#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-11314.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(84849);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/10/19 22:49:05 $");

  script_xref(name:"FEDORA", value:"2015-11314");

  script_name(english:"Fedora 21 : drupal7-migrate-2.8-1.fc21 (2015-11314)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"## 7.x-2.8

**See [SA-CONTRIB-2015-130](https://www.drupal.org/node/2516678)**

**Features and enhancements**

  - Issue #2379289: migrate-import --update does not seem to
    work as expected, if map is not joinable, due to
    highwater field?

    - Issue #2403643: Migration::applyMappings() unable to
      handle multifield subfields

    - Issue #2472045: Add language subfields only if field
      is translatable

    - Issue #2474809: Obtuse error message when migration
      dependencies are missing

    - Issue #2397791: MigrationBase::handleException should
      handle multiple errors via field_attach_validate()

    - Issue #2309563: Add support for running migrations via
      wildcard name

    - Issue #2095841: Add MigrationBase methods to
      enable/disable mail system.

    - Issue #2419373: Performance improvement when using
      Source migrations in combination with MigrateSQLMap

    - Issue #2141687: Make error messages include more
      information when migrating files

**Bug fixes**

  - Field sanitization added to prevent possibility of XSS -
    see security advisory
    https://security.drupal.org/node/155268.

    - Issue #2447115: Mapping editor does not properly save
      XML mappings

    - Issue #2497015: Remapping taxonomy terms breaks term
      reference import on dependant migrations

    - Issue #2488560: MigrateSourceList and
      MigrateSourceMultiItems getNextRow() stops after only
      one iteration

    - Issue #2446105: Source fields getting reset as 'do not
      migrate' after mapping and saving

    - Issue #2415977: /tmp is hard-coded in migrate_ui

    - Issue #2475473: Drush idlist option broken

    - Issue #2465387: Unknown option: --stop during
      migrate-import via Drush

**Important: If you are upgrading from Migrate 2.5 or earlier**

Migration developers will need to add the 'advanced migration
information' permission to their roles to continue seeing all the info
in the UI they're used to.

Auto-registration (having classes be registered just based on their
class name, with no call to registerMigration or definition in
hook_migrate_api()) is no longer supported. Registration of classes
defined in hook_migrate_api() is no longer automatic - do a drush
migrate-register or use the Register button in the UI to register
them.

Migration class constructors should now always accept an $arguments
array as the first parameter and pass it to its parent. This version
does support legacy migrations which pass a group object, or nothing,
but these methods are deprecated.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1238486"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-July/162164.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a278f0ba"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.drupal.org/node/155268."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.drupal.org/node/2516678"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected drupal7-migrate package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:drupal7-migrate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:21");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/20");
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
if (rpm_check(release:"FC21", reference:"drupal7-migrate-2.8-1.fc21")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "drupal7-migrate");
}
