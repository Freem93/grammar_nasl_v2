#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1782-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(86490);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/11 13:40:22 $");

  script_cve_id("CVE-2014-7815", "CVE-2015-5154", "CVE-2015-5278", "CVE-2015-5279", "CVE-2015-6855");
  script_bugtraq_id(70998);
  script_osvdb_id(113748, 125389, 127378, 127493, 127494);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : qemu (SUSE-SU-2015:1782-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"qemu was updated to fix several security issues and bugs.

The following vulnerabilities were fixed :

  - CVE-2015-5154: Heap-based buffer overflow in the IDE
    subsystem in QEMU, when the container has a CDROM drive
    enabled, allows local guest users to execute arbitrary
    code on the host via unspecified ATAPI commands.
    (bsc#938344).

  - CVE-2015-5278: QEMU was vulnerable to an infinite loop
    issue that could occur when receiving packets over the
    network. (bsc#945989)

  - CVE-2015-5279: QEMU was vulnerable to a heap buffer
    overflow issue that could occur when receiving packets
    over the network. (bsc#945987)

  - CVE-2015-6855: QEMU was vulnerable to a divide by zero
    issue that could occur while executing an IDE command
    WIN_READ_NATIVE_MAX to determine the maximum size of a
    drive. (bsc#945404)

  - CVE-2014-7815: The set_pixel_format function in ui/vnc.c
    in QEMU allowed remote attackers to cause a denial of
    service (crash) via a small bytes_per_pixel value.
    (bsc#902737) :

Also these non-security issues were fixed :

  - bsc#937572: Fixed dictzip on big endian systems

  - bsc#934517: Fix 'info tlb' causes guest to freeze

  - bsc#934506: Fix vte monitor consol looks empy

  - bsc#937125: Fix parsing of scsi-disk wwn uint64 property

  - bsc#945778: Drop .probe hooks for DictZip and tar block
    drivers

  - bsc#937572: Fold common-obj-y -> block-obj-y change into
    original patches

  - bsc#928308,bsc#944017: Fix virtio-ccw index errors when
    initrd gets too large

  - bsc#936537: Fix possible qemu-img error when converting
    to compressed qcow2 image

  - bsc#939216: Fix reboot fail after install using uefi

  - bsc#943446: qemu-img convert doesn't create MB aligned
    VHDs anymore

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/902737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/928308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/934506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/934517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936537"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/938344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/939216"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/943446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/944017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945987"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-7815.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5154.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5278.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5279.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6855.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151782-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c01d1067"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-715=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-715=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-s390-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-x86-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"qemu-block-rbd-2.0.2-48.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"qemu-block-rbd-debuginfo-2.0.2-48.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"qemu-x86-2.0.2-48.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"qemu-x86-debuginfo-2.0.2-48.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"qemu-s390-2.0.2-48.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"qemu-s390-debuginfo-2.0.2-48.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"qemu-2.0.2-48.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"qemu-block-curl-2.0.2-48.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"qemu-block-curl-debuginfo-2.0.2-48.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"qemu-debugsource-2.0.2-48.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"qemu-guest-agent-2.0.2-48.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"qemu-guest-agent-debuginfo-2.0.2-48.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"qemu-lang-2.0.2-48.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"qemu-tools-2.0.2-48.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"qemu-tools-debuginfo-2.0.2-48.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"qemu-kvm-2.0.2-48.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"qemu-2.0.2-48.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"qemu-block-curl-2.0.2-48.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"qemu-block-curl-debuginfo-2.0.2-48.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"qemu-debugsource-2.0.2-48.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"qemu-kvm-2.0.2-48.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"qemu-tools-2.0.2-48.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"qemu-tools-debuginfo-2.0.2-48.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"qemu-x86-2.0.2-48.9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"qemu-x86-debuginfo-2.0.2-48.9.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu");
}
