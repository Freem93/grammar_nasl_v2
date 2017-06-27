#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-2923.
#

include("compat.inc");

if (description)
{
  script_id(81716);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/28 14:03:23 $");

  script_cve_id("CVE-2014-8242");
  script_xref(name:"FEDORA", value:"2015-2923");

  script_name(english:"Fedora 22 : csync2-1.34-15.fc22 / duplicity-0.6.25-3.fc22 / librsync-1.0.0-1.fc22 / etc (2015-2923)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Changes in librsync 1.0.0 (2015-01-23)
======================================

  - SECURITY: CVE-2014-8242: librsync previously used a
    truncated MD4 'strong' check sum to match blocks.
    However, MD4 is not cryptographically strong. It's
    possible that an attacker who can control the contents
    of one part of a file could use it to control other
    regions of the file, if it's transferred using
    librsync/rdiff. For example this might occur in a
    database, mailbox, or VM image containing some
    attacker-controlled data. To mitigate this issue,
    signatures will by default be computed with a 256-bit
    BLAKE2 hash. Old versions of librsync will complain
    about a bad magic number when given these signature
    files. Backward compatibility can be obtained using the
    new `rdiff sig --hash=md4` option or through specifying
    the 'signature magic' in the API, but this should not be
    used when either the old or new file contain untrusted
    data. Deltas generated from those signatures will also
    use BLAKE2 during generation, but produce output that
    can be read by old versions. See
    https://github.com/librsync/librsync/issues/5. Thanks to
    Michael Samuel <miknet.net> for reporting this and
    offering an initial patch.

    - Various build fixes, thanks Timothy Gu.

    - Improved rdiff man page from Debian.

    - Improved librsync.spec file for building RPMs.

    - Fixed bug #1110812 'internal error: job made no
      progress'; on large files.

    - Moved hosting to https://github.com/librsync/librsync/

    - Travis-CI.org integration test at
      https://travis-ci.org/librsync/librsync/

    - Remove bundled copy of popt; it must be installed
      separately.

    - You can set `$LIBTOOLIZE` before running `autogen.sh`,
      for example on OS X Homebrew where it is called
      `glibtoolize`.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1126712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/librsync/librsync/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/librsync/librsync/issues/5."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-March/151104.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bce8644f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-March/151105.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa7b5415"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-March/151106.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2233ba5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-March/151107.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?15fa614c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://travis-ci.org/librsync/librsync/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:csync2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:duplicity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:librsync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rdiff-backup");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/10");
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
if (! ereg(pattern:"^22([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 22.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC22", reference:"csync2-1.34-15.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"duplicity-0.6.25-3.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"librsync-1.0.0-1.fc22")) flag++;
if (rpm_check(release:"FC22", reference:"rdiff-backup-1.2.8-14.fc22")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "csync2 / duplicity / librsync / rdiff-backup");
}
