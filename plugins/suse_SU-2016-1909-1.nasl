#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1909-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93185);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2015-8918", "CVE-2015-8919", "CVE-2015-8920", "CVE-2015-8921", "CVE-2015-8922", "CVE-2015-8923", "CVE-2015-8924", "CVE-2015-8925", "CVE-2015-8926", "CVE-2015-8928", "CVE-2015-8929", "CVE-2015-8930", "CVE-2015-8931", "CVE-2015-8932", "CVE-2015-8933", "CVE-2015-8934", "CVE-2016-4300", "CVE-2016-4301", "CVE-2016-4302", "CVE-2016-4809");
  script_osvdb_id(118200, 118251, 118253, 118254, 118255, 118256, 118257, 118259, 118650, 119727, 122496, 140116, 140246, 140247, 140248, 140478, 140479, 140480, 140481, 140484);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : libarchive (SUSE-SU-2016:1909-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libarchive was updated to fix 20 security issues. These security
issues were fixed :

  - CVE-2015-8918: Overlapping memcpy in CAB parser
    (bsc#985698).

  - CVE-2015-8919: Heap out of bounds read in LHA/LZH parser
    (bsc#985697).

  - CVE-2015-8920: Stack out of bounds read in ar parser
    (bsc#985675).

  - CVE-2015-8921: Global out of bounds read in mtree parser
    (bsc#985682).

  - CVE-2015-8922: NULL pointer access in 7z parser
    (bsc#985685).

  - CVE-2015-8923: Unclear crashes in ZIP parser
    (bsc#985703).

  - CVE-2015-8924: Heap buffer read overflow in tar
    (bsc#985609).

  - CVE-2015-8925: Unclear invalid memory read in mtree
    parser (bsc#985706).

  - CVE-2015-8926: NULL pointer access in RAR parser
    (bsc#985704).

  - CVE-2015-8928: Heap out of bounds read in mtree parser
    (bsc#985679).

  - CVE-2015-8929: Memory leak in tar parser (bsc#985669).

  - CVE-2015-8930: Endless loop in ISO parser (bsc#985700).

  - CVE-2015-8931: Undefined behavior / signed integer
    overflow in mtree parser (bsc#985689).

  - CVE-2015-8932: Compress handler left shifting larger
    than int size (bsc#985665).

  - CVE-2015-8933: Undefined behavior / signed integer
    overflow in TAR parser (bsc#985688).

  - CVE-2015-8934: Out of bounds read in RAR (bsc#985673).

  - CVE-2016-4300: Heap buffer overflow vulnerability in the
    7zip read_SubStreamsInfo (bsc#985832).

  - CVE-2016-4301: Stack buffer overflow in the mtree
    parse_device (bsc#985826).

  - CVE-2016-4302: Heap buffer overflow in the Rar
    decompression functionality (bsc#985835).

  - CVE-2016-4809: Memory allocate error with symbolic links
    in cpio archives (bsc#984990).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985679"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985704"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8918.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8919.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8920.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8921.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8922.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8923.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8924.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8925.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8926.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8928.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8929.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8930.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8931.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8932.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8933.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8934.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4300.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4301.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4302.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4809.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161909-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cbcc4a73"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2016-1123=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2016-1123=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2016-1123=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libarchive-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libarchive13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libarchive13-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (os_ver == "SLES12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"libarchive-debugsource-3.1.2-22.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libarchive13-3.1.2-22.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libarchive13-debuginfo-3.1.2-22.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libarchive-debugsource-3.1.2-22.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libarchive13-3.1.2-22.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libarchive13-debuginfo-3.1.2-22.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libarchive");
}
