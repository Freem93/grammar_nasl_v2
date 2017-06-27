#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-2462.
#

include("compat.inc");

if (description)
{
  script_id(27773);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:54:55 $");

  script_cve_id("CVE-2007-5191");
  script_xref(name:"FEDORA", value:"2007-2462");

  script_name(english:"Fedora 7 : util-linux-2.13-0.54.1.fc7 (2007-2462)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Mon Oct 8 2007 Karel Zak <kzak at redhat.com>
    2.13-0.54.1

    - fix #320131 - CVE-2007-5191 util-linux (u)mount
      doesn't drop privileges properly when calling helpers
      [F7]

    - Wed Aug 8 2007 Karel Zak <kzak at redhat.com>
      2.13-0.54

    - backport mount relatime patch

    - Thu Aug 2 2007 Karel Zak <kzak at redhat.com>
      2.13-0.53

    - fix #236848 - mount/fstab.c:lock_mtab() should open
      with proper permissions

    - fix #238918 - blockdev --getsize does not work
      properly on devices with more than 2^31 sectors

    - Mon Jul 9 2007 Karel Zak <kzak at redhat.com>
      2.13-0.52

    - fix #245578 - login's PAM configuration inits the
      keyring at an inconvenient time

    - fix #231532 - 'pamconsole' not documented in mount(8)

    - fix #243930 - translation files exist, but are not
      being used

    - fix #228731 - sfdisk doesn't support DM-MP device (add
      default heads and sectors)

    - fix #231192 - ipcs is not printing correct values on
      pLinux

    - fix #245912 - mount doesn't write the 'loop=...'
      option in /etc/mtab when mounting a loop device

    - fix #213253 - 'cal -3' generates improperly formatted
      output

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=320041"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-October/004114.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1430300c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected util-linux and / or util-linux-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:util-linux-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"util-linux-2.13-0.54.1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"util-linux-debuginfo-2.13-0.54.1.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "util-linux / util-linux-debuginfo");
}
