#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99801);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/02 13:34:09 $");

  script_cve_id(
    "CVE-2015-0247",
    "CVE-2015-1572"
  );
  script_bugtraq_id(
    72520,
    72709
  );
  script_osvdb_id(
    118193
  );

  script_name(english:"EulerOS 2.0 SP1 : e2fsprogs (EulerOS-SA-2016-1038)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the e2fsprogs packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The e2fsprogs package contains a number of utilities
    for creating, checking, modifying, and correcting any
    inconsistencies in second, third and fourth extended
    (ext2/ext3/ext4) filesystems. E2fsprogs contains e2fsck
    (used to repair filesystem inconsistencies after an
    unclean shutdown), mke2fs (used to initialize a
    partition to contain an empty ext2 filesystem), debugfs
    (used to examine the internal structure of a
    filesystem, to manually repair a corrupted filesystem,
    or to create test cases for e2fsck), tune2fs (used to
    modify filesystem parameters), and most of the other
    core ext2fs filesystem utilities.

  - You should install the e2fsprogs package if you need to
    manage the performance of an ext2, ext3, or ext4
    filesystem.

  - Security Fix(es)

  - Heap-based buffer overflow in closefs.c in the
    libext2fs library in e2fsprogs before 1.42.12 allows
    local users to execute arbitrary code by causing a
    crafted block group descriptor to be marked as dirty.
    NOTE: this vulnerability exists because of an
    incomplete fix for CVE-2015-0247.(CVE-2015-1572)

  - Heap-based buffer overflow in openfs.c in the libext2fs
    library in e2fsprogs before 1.42.12 allows local users
    to execute arbitrary code via crafted block group
    descriptor data in a filesystem image.(CVE-2015-0247)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1038
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08a53e20");
  script_set_attribute(attribute:"solution", value:
"Update the affected e2fsprogs packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:e2fsprogs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:e2fsprogs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:e2fsprogs-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libcom_err");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libcom_err-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(1)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1");

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

flag = 0;

pkgs = ["e2fsprogs-1.42.9-7.h2",
        "e2fsprogs-devel-1.42.9-7.h2",
        "e2fsprogs-libs-1.42.9-7.h2",
        "libcom_err-1.42.9-7.h2",
        "libcom_err-devel-1.42.9-7.h2",
        "libss-1.42.9-7.h2"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "e2fsprogs");
}
