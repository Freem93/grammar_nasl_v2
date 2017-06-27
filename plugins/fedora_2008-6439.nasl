#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-6439.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(33520);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 22:23:16 $");

  script_bugtraq_id(30141, 30143, 30146);
  script_xref(name:"FEDORA", value:"2008-6439");

  script_name(english:"Fedora 9 : java-1.6.0-openjdk-1.6.0.0-0.16.b09.fc9 (2008-6439)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Tue Jul 8 2008 Lillian Angel <langel at redhat.com> -
    1:1.6.0-0.16.b09

    - Only apply hotspot security patch of jitarches.

    - Wed Jul 2 2008 Lillian Angel <langel at redhat.com> -
      1:1.6.0-0.16.b09

    - Added OpenJDK security patches.

    - Sat Jun 7 2008 Tom 'spot' Callaway <tcallawa at
      redhat.com> - 1:1.6.0-0.16.b09

    - enable sparc/sparc64 builds

    - Sat May 31 2008 Thomas Fitzsimmons <fitzsim at
      redhat.com> - 1:1.6.0.0-0.15.b09

    - Fix keytool location passed to generate-cacerts.pl.

    - Fri May 30 2008 Thomas Fitzsimmons <fitzsim at
      redhat.com> - 1:1.6.0.0-0.15.b09

    - Generate cacerts file.

    - Fri May 30 2008 Thomas Fitzsimmons <fitzsim at
      redhat.com> - 1:1.6.0.0-0.15.b09

    - Remove jhat patch.

    - Fri May 30 2008 Thomas Fitzsimmons <fitzsim at
      redhat.com> - 1:1.6.0.0-0.15.b09

    - Remove makefile patch.

    - Update generate-fedora-zip.sh.

    - Fri May 30 2008 Thomas Fitzsimmons <fitzsim at
      redhat.com> - 1:1.6.0.0-0.15.b09

    - Formatting cleanups.

    - Fri May 30 2008 Thomas Fitzsimmons <fitzsim at
      redhat.com> - 1:1.6.0.0-0.15.b09

    - Group all Mauve commands.

    - Fri May 30 2008 Thomas Fitzsimmons <fitzsim at
      redhat.com> - 1:1.6.0.0-0.15.b09

    - Formatting cleanups.

    - Add jtreg_output to src subpackage.

    - Wed May 28 2008 Lillian Angel <langel at redhat.com> -
      1:1.6.0.0-0.15.b09

    - Updated icedteasnapshot for new release.

    - Tue May 27 2008 Thomas Fitzsimmons <fitzsim at
      redhat.com> - 1:1.6.0.0-0.15.b09

    - Require ca-certificates.

    - Symlink to ca-certificates cacerts.

    - Remove cacerts from files list.

    - Resolves: rhbz#444260

    - Mon May 26 2008 Lillian Angel <langel at redhat.com> -
      1:1.6.0.0-0.14.b09

    - Added eclipse-ecj build requirement for mauve.

    - Updated icedteasnapshot.

    - Fri May 23 2008 Lillian Angel <langel at redhat.com> -
      1:1.6.0.0-0.14.b09

    - Fixed jtreg testing.

    - Fri May 23 2008 Lillian Angel <langel at redhat.com> -
      1:1.6.0.0-0.14.b09

    - Updated icedteasnapshot.

    - Updated release.

    - Added jtreg testing.

    - Thu May 22 2008 Lillian Angel <langel at redhat.com> -
      1:1.6.0.0-0.13.b09

    - Added new patch
      java-1.6.0-openjdk-java-access-bridge-tck.patch.

    - Updated release.

    - Mon May 5 2008 Lillian Angel <langel at redhat.com> -
      1:1.6.0.0-0.12.b09

    - Updated release.

    - Updated icedteasnapshot.

    - Resolves: rhbz#445182

    - Resolves: rhbz#445183

    - Tue Apr 29 2008 Lillian Angel <langel at redhat.com> -
      1:1.6.0.0-0.11.b09

    - Fixed javaws.desktop installation.

    - Tue Apr 29 2008 Lillian Angel <langel at redhat.com> -
      1:1.6.0.0-0.11.b09

    - Updated icedteasnapshot.

[plus 6 lines in the Changelog]

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=452649"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=452652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=452658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=452659"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012347.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?06539bb6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-openjdk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 9.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC9", reference:"java-1.6.0-openjdk-1.6.0.0-0.16.b09.fc9")) flag++;


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
