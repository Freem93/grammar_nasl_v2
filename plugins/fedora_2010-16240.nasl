#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-16240.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(50295);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/20 13:54:17 $");

  script_cve_id("CVE-2009-3555", "CVE-2010-3541", "CVE-2010-3548", "CVE-2010-3549", "CVE-2010-3551", "CVE-2010-3553", "CVE-2010-3554", "CVE-2010-3557", "CVE-2010-3561", "CVE-2010-3562", "CVE-2010-3564", "CVE-2010-3565", "CVE-2010-3567", "CVE-2010-3568", "CVE-2010-3569", "CVE-2010-3573", "CVE-2010-3574");
  script_bugtraq_id(36935, 43963, 43979, 43985, 43992, 43994, 44009, 44011, 44012, 44013, 44014, 44016, 44017, 44027, 44028, 44032, 44035);
  script_osvdb_id(69033, 69034, 69038, 69039, 69040, 69042, 69044, 69045, 69049, 69052, 69053, 69055, 69057, 69058, 69059);
  script_xref(name:"FEDORA", value:"2010-16240");

  script_name(english:"Fedora 12 : java-1.6.0-openjdk-1.6.0.0-41.1.8.2.fc12 (2010-16240)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Thu Oct 7 2010 Jiri Vanek <jvanek at redhat.com>
    -1:1.6.0-41.1.8.2

    - Imports icedtea6-1.8.2

    - changed Release versioning from openjdkver to
      icedteaver

    - Resolves: rhbz#533125

    - Resolves: rhbz#639876

    - Resolves: rhbz#639880

    - Resolves: rhbz#639897

    - Resolves: rhbz#639904

    - Resolves: rhbz#639909

    - Resolves: rhbz#639914

    - Resolves: rhbz#639920

    - Resolves: rhbz#639922

    - Resolves: rhbz#639925

    - Resolves: rhbz#639951

    - Resolves: rhbz#6622002

    - Resolves: rhbz#6623943

    - Resolves: rhbz#6925672

    - Resolves: rhbz#6952017

    - Resolves: rhbz#6952603

    - Resolves: rhbz#6961084

    - Resolves: rhbz#6963285

    - Resolves: rhbz#6980004

    - Resolves: rhbz#6981426

    - Resolves: rhbz#6990437

    - Mon Jul 26 2010 Martin Matejovic <mmatejov at
      redhat.com> -1:1.6.0-40.b18

    - Imports icedtea6-1.8.1

    - Removed: java-1.6.0-openjdk-plugin.patch

    - Resolves: rhbz#616893

    - Resolves: rhbz#616895

    - Mon Jun 14 2010 Martin Matejovic <mmatejov at
      redhat.com> -1:1.6.0.-39.b18

    - Fixed plugin update to IcedTeaPlugin.so

    - Fixed plugin cpu usage issue

    - Fixed plugin rewrites ? in URL

    - Added java-1.6.0-openjdk-plugin.patch

    - Resovles: rhbz#598353

    - Resolves: rhbz#592553

    - Resolves: rhbz#602906

    - Tue Apr 20 2010 Martin Matejovic <mmatejov at
      redhat.com> - 1:1.6.0-38.b18

    - Added icedtea6-1.8

    - Added openjdk b18

    - Added jdk6-jaf-2009_10_27.zip as SOURCE9

    - Added jdk6-jaxp-2009_10_13.zip as SOURCE10

    - Added jdk6-jaxws-2009_10_27.zip as SOURCE11

    - Removed
      java-1.6.0-openjdk-securitypatches-20100323.patch

    - Removed java-1.6.0-openjdk-linux-globals.patch

    - Removed java-1.6.0-openjdk-memory-barriers.patch

    - Removed java-1.6.0-openjdk-pulse-audio-libs.patch

    - Enabled NPPlugin

    - Tue Mar 30 2010 Martin Matejovic <mmatejov at
      redhat.com> - 1:1.6.0-37.b17

    - Added
      java-1.6.0-openjdk-securitypatches-20100323.patch

[plus 62 lines in the Changelog]

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=533125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=639876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=639880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=639897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=639904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=639909"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=639914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=639920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=639925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=642167"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=642180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=642187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=642197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=642202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=642215"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-October/049702.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?407b0f07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-openjdk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^12([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 12.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC12", reference:"java-1.6.0-openjdk-1.6.0.0-41.1.8.2.fc12")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-openjdk");
}
