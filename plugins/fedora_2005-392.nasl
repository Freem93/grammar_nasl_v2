#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-392.
#

include("compat.inc");

if (description)
{
  script_id(18377);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:38:04 $");

  script_xref(name:"FEDORA", value:"2005-392");

  script_name(english:"Fedora Core 3 : kernel-2.6.11-1.27_FC3 (2005-392)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Tue May 17 2005 Dave Jones <davej at redhat.com>

    - Remove the unused (and outdated) Xen patches from the
      FC3 tree.

  - Mon May 16 2005 Dave Jones <davej at redhat.com>

    - Rebase to 2.6.11.10, (fixing CVE-2005-1264)

  - Thu May 12 2005 Dave Jones <davej at redhat.com>

    - Rebase to 2.6.11.9, (fixing CVE-2005-1263)

  - Tue May 10 2005 Dave Jones <davej at redhat.com>

    - Fix two bugs in x86-64 page fault handler.

  - Mon May 9 2005 Dave Jones <davej at redhat.com>

    - Rebase to 2.6.11.8 |<i> Fixes CVE-2005-1368 (local DoS
      in key lookup). (#156680) </I>|<i> Fixes CVE-2005-1369
      (i2c alarms sysfs DoS). (#156683) </I>- Merge IDE
      fixes from 2.6.11-ac7

  - Add Conflicts for older IPW firmwares.

    - Fix conntrack leak with raw sockets.

  - Sun May 1 2005 Dave Jones <davej at redhat.com>

    - Various firewire fixes backported from -mm. (#133798)
      (Thanks to Jody McIntyre for doing this)

  - Fri Apr 29 2005 Dave Jones <davej at redhat.com>

    - fix oops in aacraid open when using adaptec tools.
      (#148761)

    - Blacklist another brainless SCSI scanner. (#155457)

  - Thu Apr 21 2005 Dave Jones <davej at redhat.com>

    - Fix up SCSI queue locking. (#155472)

  - Tue Apr 19 2005 Dave Jones <davej at redhat.com>

    - SCSI tape security: require CAP_ADMIN for SG_IO etc.
      (#155355)

  - Mon Apr 18 2005 Dave Jones <davej at redhat.com>

    - Retry more aggressively during USB device
      initialization

  - Thu Apr 14 2005 Dave Jones <davej at redhat.com>

    - Build DRM modular. (#154769)

  - Fri Apr 8 2005 Dave Jones <davej at redhat.com>

    - Disable Longhaul driver (again).

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-May/000916.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8ac50a02"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 3.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC3", reference:"kernel-2.6.11-1.27_FC3")) flag++;
if (rpm_check(release:"FC3", reference:"kernel-debuginfo-2.6.11-1.27_FC3")) flag++;
if (rpm_check(release:"FC3", reference:"kernel-doc-2.6.11-1.27_FC3")) flag++;
if (rpm_check(release:"FC3", reference:"kernel-smp-2.6.11-1.27_FC3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-doc / kernel-smp");
}
