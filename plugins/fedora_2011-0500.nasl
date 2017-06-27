#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-0500.
#

include("compat.inc");

if (description)
{
  script_id(51580);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/20 21:47:27 $");

  script_cve_id("CVE-2010-4351");
  script_osvdb_id(70605);
  script_xref(name:"FEDORA", value:"2011-0500");

  script_name(english:"Fedora 13 : java-1.6.0-openjdk-1.6.0.0-48.1.8.4.fc13 (2011-0500)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Wed Jan 5 2011 Jiri Vanek <jvanek at redhat.com>
    -1:1.6.0-47.1.8.4.48

    - updated to icedtea 1.8.4

    - Mon Nov 29 2010 Jiri Vanek <jvanek at redhat.com>
      -1:1.6.0-46.1.8.3.4

    - Resolves: rhbz#657491

    - Removed Asian and Indic font dependencies.

    - Fri Nov 19 2010 Jiri Vanek <jvanek at redhat.com>
      -1:1.6.0-45.1.8.3

    - updated to iced tea 1.8.3

    - added fonts dependencies

    - Tue Nov 2 2010 Jiri Vanek <jvanek at redhat.com>
      -1:1.6.0-44.1.8.2 -fixing rhbz#648499 - BuildRequires:
      redhat-lsb

  - Thu Oct 7 2010 Jiri Vanek <jvanek at redhat.com>
    -1:1.6.0-43.1.8.2

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
      redhat.com> -1:1.6.0-42.b18

    - Imports icedtea6-1.8.1

    - Removed: java-1.6.0-openjdk-plugin.patch

    - Resolves: rhbz#616893

    - Resolves: rhbz#616895

    - Mon Jun 14 2010 Martin Matejovic <mmatejov at
      redhat.com> -1:1.6.0.-41.b18

    - Fixed plugin update to IcedTeaPlugin.so

    - Fixed plugin cpu usage issue

    - Fixed plugin rewrites ? in URL

    - Added java-1.6.0-openjdk-plugin.patch

    - Resovles: rhbz#598353

    - Resolves: rhbz#592553

    - Resolves: rhbz#602906

    - Fri Jun 11 2010 Martin Matejovic <mmatejov at
      redhat.com> - 1:1.6.0-40.b18

    - Rebuild

    - Tue Jun 8 2010 Martin Matejovic <mmatejov at
      redhat.com> - 1:1.6.0-39.b18

[plus 15 lines in the Changelog]

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=663680"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-January/053288.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1526a2c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-openjdk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:13");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^13([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 13.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC13", reference:"java-1.6.0-openjdk-1.6.0.0-48.1.8.4.fc13")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-openjdk");
}
