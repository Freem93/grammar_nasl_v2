#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(81481);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/02/24 14:41:20 $");

  script_cve_id("CVE-2014-3633", "CVE-2014-3640", "CVE-2014-3657", "CVE-2014-7823", "CVE-2014-7840", "CVE-2014-8106");

  script_name(english:"SuSE 11.3 Security Update : kvm and libvirt (SAT Patch Number 10222)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This collective update for KVM and libvirt provides fixes for security
and non-security issues.

kvm :

  - Fix NULL pointer dereference because of uninitialized
    UDP socket. (bsc#897654, CVE-2014-3640)

  - Fix performance degradation after migration.
    (bsc#878350)

  - Fix potential image corruption due to missing
    FIEMAP_FLAG_SYNC flag in FS_IOC_FIEMAP ioctl.
    (bsc#908381)

  - Add validate hex properties for qdev. (bsc#852397)

  - Add boot option to do strict boot (bsc#900084)

  - Add query-command-line-options QMP command. (bsc#899144)

  - Fix incorrect return value of migrate_cancel.
    (bsc#843074)

  - Fix insufficient parameter validation during ram load.
    (bsc#905097, CVE-2014-7840)

  - Fix insufficient blit region checks in qemu/cirrus.
    (bsc#907805, CVE-2014-8106) libvirt :

  - Fix security hole with migratable flag in dumpxml.
    (bsc#904176, CVE-2014-7823)

  - Fix domain deadlock. (bsc#899484, CVE-2014-3657)

  - Use correct definition when looking up disk in qemu
    blkiotune. (bsc#897783, CVE-2014-3633)

  - Fix undefined symbol when starting virtlockd.
    (bsc#910145)

  - Add '-boot strict' to qemu's commandline whenever
    possible. (bsc#900084)

  - Add support for 'reboot-timeout' in qemu. (bsc#899144)

  - Increase QEMU's monitor timeout to 30sec. (bsc#911742)

  - Allow setting QEMU's migration max downtime any time.
    (bsc#879665)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=843074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=852397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=878350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=879665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=897654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=897783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=899144"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=899484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=900084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=904176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=905097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=907805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=908381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=910145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=911742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3633.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3640.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3657.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-7823.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-7840.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8106.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 10222.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libvirt-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libvirt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"kvm-1.4.2-0.21.5")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libvirt-1.0.5.9-0.19.3")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libvirt-client-1.0.5.9-0.19.3")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libvirt-client-32bit-1.0.5.9-0.19.5")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libvirt-doc-1.0.5.9-0.19.3")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libvirt-lock-sanlock-1.0.5.9-0.19.3")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libvirt-python-1.0.5.9-0.19.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
