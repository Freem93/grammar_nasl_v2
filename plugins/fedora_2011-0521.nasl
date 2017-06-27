#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-0521.
#

include("compat.inc");

if (description)
{
  script_id(51581);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/20 21:47:27 $");

  script_cve_id("CVE-2010-4351");
  script_osvdb_id(70605);
  script_xref(name:"FEDORA", value:"2011-0521");

  script_name(english:"Fedora 14 : java-1.6.0-openjdk-1.6.0.0-50.1.9.4.fc14 (2011-0521)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Wed Jan 5 2011 Jiri Vanek <jvanek at redhat.com> -
    1:1.6.0.0-50.1.9.4

    - Updated to IcedTea 1.9.4

    - Wed Dec 1 2010 Deepak Bhole <dbhole at redhat.com> -
      1:1.6.0.0-49.1.9.3

    - Updated to IcedTea 1.9.3

    - Re-enable Compressed Oops by default as upstream bug#
      7002666 is fixed

    - Tue Nov 30 2010 Deepak Bhole <dbhole at redhat.com> -
      1:1.6.0.0-49.1.9.2

    - Update to IcedTea 1.9.2

    - Resolves: rhbz# 645843

    - Resolves: rhbz# 647737

    - Resolves: rhbz# 643674

    - Remove patch that disabled Compressed Oops. It is now
      the default upstream.

    - Mon Nov 29 2010 Jiri Vanek <jvanek at redhat.com>
      -1:1.6.0-48.1.9.1

    - Resolves: rhbz#657491

    - Removed Asian and Indic font dependencies.

    - Mon Nov 22 2010 Jiri Vanek <jvanek at redhat.com>
      -1:1.6.0-47.1.9.1

    - added fonts dependencies

    - Mon Nov 8 2010 Deepak Bhole <dbhole at redhat.com> -
      1:1.6.0.0-46.1.9.1

    - Temporarily resolve rhbz#647737 :

    - Put hs19 back, but disable Compressed Oops

    - Mon Nov 8 2010 Deepak Bhole <dbhole at redhat.com> -
      1:1.6.0.0-45.1.9.1

    - Temporarily resolve rhbz#647737 :

    - Build with default hotspot (hs17)

    - From Jiri Vanek (jvanek at redhat.com): -Fixing
      rhbz#648499 - BuildRequires: redhat-lsb

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=663680"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-January/053276.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1bddd5fb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-openjdk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

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
if (! ereg(pattern:"^14([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 14.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC14", reference:"java-1.6.0-openjdk-1.6.0.0-50.1.9.4.fc14")) flag++;


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
