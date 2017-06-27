#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99808);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/04 13:21:27 $");

  script_cve_id(
    "CVE-2015-8916",
    "CVE-2015-8917",
    "CVE-2015-8919",
    "CVE-2015-8920",
    "CVE-2015-8921",
    "CVE-2015-8922",
    "CVE-2015-8923",
    "CVE-2015-8924",
    "CVE-2015-8925",
    "CVE-2015-8926",
    "CVE-2015-8928",
    "CVE-2015-8930",
    "CVE-2015-8931",
    "CVE-2015-8932",
    "CVE-2015-8934",
    "CVE-2016-1541",
    "CVE-2016-4300",
    "CVE-2016-4302",
    "CVE-2016-4809",
    "CVE-2016-5418",
    "CVE-2016-5844",
    "CVE-2016-6250",
    "CVE-2016-7166"
  );
  script_osvdb_id(
    118200,
    118251,
    118253,
    118254,
    118255,
    118256,
    118257,
    118650,
    118657,
    119727,
    122496,
    134334,
    134899,
    139654,
    140116,
    140246,
    140248,
    140356,
    140479,
    140480,
    140481,
    140489,
    142331
  );

  script_name(english:"EulerOS 2.0 SP1 : libarchive (EulerOS-SA-2016-1045)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libarchive package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A flaw was found in the way libarchive handled hardlink
    archive entries of non-zero size. Combined with flaws
    in libarchive's file system sandboxing, this issue
    could cause an application using libarchive to
    overwrite arbitrary files with arbitrary data from the
    archive. (CVE-2016-5418)

  - Multiple out-of-bounds write flaws were found in
    libarchive.

  - Specially crafted ZIP, 7ZIP, or RAR files could cause a
    heap overflow, potentially allowing code execution in
    the context of the application using libarchive.
    (CVE-2016-1541, CVE-2016-4300, CVE-2016-4302)

  - Multiple out-of-bounds read flaws were found in
    libarchive.

  - Specially crafted LZA/LZH, AR, MTREE, ZIP, TAR, or RAR
    files could cause the application to read data out of
    bounds, potentially disclosing a small amount of
    application memory, or causing an application crash.
    (CVE-2015-8919, CVE-2015-8920, CVE-2015-8921,
    CVE-2015-8923, CVE-2015-8924, CVE-2015-8925,
    CVE-2015-8926, CVE-2015-8928, CVE-2015-8934)

  - Multiple NULL pointer dereference flaws were found in
    libarchive.

  - Specially crafted RAR, CAB, or 7ZIP files could cause
    an application using libarchive to crash.
    (CVE-2015-8916, CVE-2015-8917, CVE-2015-8922)

  - Multiple infinite loop / resource exhaustion flaws were
    found in libarchive. Specially crafted GZIP or ISO
    files could cause the application to consume an
    excessive amount of resources, eventually leading to a
    crash on memory exhaustion. (CVE-2016-7166,
    CVE-2015-8930)

  - A denial of service vulnerability was found in
    libarchive. A specially crafted CPIO archive containing
    a symbolic link to a large target path could cause
    memory allocation to fail, causing an application using
    libarchive that attempted to view or extract such
    archive to crash. (CVE-2016-4809)

  - An integer overflow flaw, leading to a buffer overflow,
    was found in libarchive's construction of ISO9660
    volumes. Attempting to create an ISO9660 volume with 2
    GB or 4 GB file names could cause the application to
    attempt to allocate 20 GB of memory. If this were to
    succeed, it could lead to an out of bounds write on the
    heap and potential code execution. (CVE-2016-6250)

  - Multiple instances of undefined behavior due to
    arithmetic overflow were found in libarchive. Specially
    crafted MTREE archives, Compress streams, or ISO9660
    volumes could potentially cause the application to fail
    to read the archive, or to crash. (CVE-2015-8931,
    CVE-2015-8932, CVE-2016-5844)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1045
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?12db4627");
  script_set_attribute(attribute:"solution", value:
"Update the affected libarchive packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libarchive");
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

pkgs = ["libarchive-3.1.2-10"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libarchive");
}
