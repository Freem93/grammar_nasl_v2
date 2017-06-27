#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-2295.
#

include("compat.inc");

if (description)
{
  script_id(27764);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/10/21 21:54:55 $");

  script_cve_id("CVE-2007-5159");
  script_xref(name:"FEDORA", value:"2007-2295");

  script_name(english:"Fedora 7 : fuse-2.7.0-5.fc7 / ntfs-3g-1.913-2.fc7 (2007-2295)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that members of the group fuse can get access to
devices which they normally should not have access to. For ntfs-3g
mounts, this was because /sbin/mount.ntfs-3g was setuid root. This
update fixes /sbin/mount.ntfs-3g so that it is no longer has the
setuid bit enabled. The fuse package is also being updated to correct
an error in the previous testing package which incorrectly changed the
permissions on /dev/fuse.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=298651"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-September/003892.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?68ad6ecb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-September/003893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?672d0299"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:fuse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:fuse-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:fuse-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ntfs-3g");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ntfs-3g-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ntfs-3g-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/25");
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
if (rpm_check(release:"FC7", reference:"fuse-2.7.0-5.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"fuse-debuginfo-2.7.0-5.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"fuse-devel-2.7.0-5.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"fuse-libs-2.7.0-5.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ntfs-3g-1.913-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ntfs-3g-debuginfo-1.913-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ntfs-3g-devel-1.913-2.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fuse / fuse-debuginfo / fuse-devel / fuse-libs / ntfs-3g / etc");
}
