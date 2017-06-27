#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-7e229134f9.
#

include("compat.inc");

if (description)
{
  script_id(92445);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/18 16:52:29 $");

  script_cve_id("CVE-2015-5723");
  script_xref(name:"FEDORA", value:"2016-7e229134f9");

  script_name(english:"Fedora 23 : php-doctrine-orm (2016-7e229134f9)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"## v2.4.8

### Security

  - CVE-2015-5723 php-doctrine-orm filesystem permission
    issues

    - https://access.redhat.com/security/cve/CVE-2015-5723

    - http://www.doctrine-project.org/2015/08/31/security_misconfiguration_vulnerability_in_various_doctrine_projects.html

### Bug

  - [DDC-3310] - [GH-1138] Join column index names

  - [DDC-3343] - `PersistentCollection::removeElement`
    schedules an entity for deletion when relationship is
    EXTRA_LAZY, with `orphanRemoval` false.

  - [DDC-3464] - [GH-1231] Backport 'Merge pull request
    #1098 from encoder32/DDC-1590' to 2.4 branch

  - [DDC-3482] - [GH-1242] Attempting to lock a proxy object
    fails as UOW doesn't init proxy first

  - [DDC-3493] - New (PHP 5.5) 'class' keyword - wrong
    parsing by EntityGenerator

  - [DDC-3494] - [GH-1250] Test case for 'class' keyword

  - [DDC-3500] - [GH-1254] Fix applying ON/WITH conditions
    to first join in Class Table Inheritance

  - [DDC-3502] - [GH-1256] DDC-3493 - fixed EntityGenerator
    parsing for php 5.5 '::class' syntax

  - [DDC-3518] - [GH-1266] [2.4] Fix schema generation in
    the test suite

  - [DDC-3537] - [GH-1282] Hotfix/#1169 extra lazy one to
    many should not delete referenced entities (backport to
    2.4)

  - [DDC-3551] - [GH-1294] Avoid Connection error when
    calling ClassMetadataFactor::getAllMetadata()

  - [DDC-3560] - [GH-1300] [2.4] #1169 DDC-3343 one-to-omany
    persister deletes only on EXTRA_LAZY plus orphanRemoval

  - [DDC-3608] - [GH-1327] Properly generate default value
    from yml & xml mapping

  - [DDC-3619] - spl_object_hash collision

  - [DDC-3624] - [GH-1338] [DDC-3619] Update identityMap
    when entity gets managed again

  - [DDC-3643] - [GH-1352] fix EntityGenerator
    RegenerateEntityIfExists

### Improvement

  - [DDC-3530] - [GH-1276] travis: run coverage just once

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-7e229134f9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-doctrine-orm package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-doctrine-orm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:23");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/20");
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
if (! ereg(pattern:"^23([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 23", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC23", reference:"php-doctrine-orm-2.4.8-1.fc23")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-doctrine-orm");
}
