#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2775-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(94728);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/02/27 15:13:34 $");

  script_cve_id("CVE-2008-3522", "CVE-2014-8158", "CVE-2015-5203", "CVE-2015-5221", "CVE-2016-1577", "CVE-2016-1867", "CVE-2016-2089", "CVE-2016-2116", "CVE-2016-8690", "CVE-2016-8691", "CVE-2016-8692", "CVE-2016-8693", "CVE-2016-8880", "CVE-2016-8881", "CVE-2016-8882", "CVE-2016-8883", "CVE-2016-8884", "CVE-2016-8885", "CVE-2016-8886", "CVE-2016-8887");
  script_bugtraq_id(31470, 72293);
  script_osvdb_id(49890, 77595, 77596, 115355, 117409, 126344, 126557, 132886, 133755, 135285, 135286, 143483, 143484, 143485, 145760, 145761, 145762, 145771, 146062);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : jasper (SUSE-SU-2016:2775-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for jasper to version 1.900.14 fixes several issues. These
security issues were fixed :

  - CVE-2016-8887: NULL pointer dereference in
    jp2_colr_destroy (jp2_cod.c) (bsc#1006836)

  - CVE-2016-8886: memory allocation failure in jas_malloc
    (jas_malloc.c) (bsc#1006599)

  - CVE-2016-8884,CVE-2016-8885: two NULL pointer
    dereferences in bmp_getdata (incomplete fix for
    CVE-2016-8690) (bsc#1007009)

  - CVE-2016-8883: assert in jpc_dec_tiledecode()
    (bsc#1006598)

  - CVE-2016-8882: segfault / NULL pointer access in
    jpc_pi_destroy (bsc#1006597)

  - CVE-2016-8881: Heap overflow in jpc_getuint16()
    (bsc#1006593)

  - CVE-2016-8880: Heap overflow in jpc_dec_cp_setfromcox()
    (bsc#1006591)

  - CVE-2016-8693 Double free vulnerability in mem_close
    (bsc#1005242)

  - CVE-2016-8691, CVE-2016-8692: Divide by zero in
    jpc_dec_process_siz (bsc#1005090)

  - CVE-2016-8690: NULL pointer dereference in bmp_getdata
    triggered by crafted BMP image (bsc#1005084)

  - CVE-2016-2116: Memory leak in the
    jas_iccprof_createfrombuf function in JasPer allowed
    remote attackers to cause a denial of service (memory
    consumption) via a crafted ICC color profile in a JPEG
    2000 image file (bsc#968373)

  - CVE-2016-2089: invalid read in the JasPer's
    jas_matrix_clip() function (bsc#963983)

  - CVE-2016-1867: Out-of-bounds Read in the JasPer's
    jpc_pi_nextcprl() function (bsc#961886)

  - CVE-2015-5221: Use-after-free (and double-free) in
    Jasper JPEG-200 (bsc#942553).

  - CVE-2015-5203: Double free corruption in JasPer
    JPEG-2000 implementation (bsc#941919)

  - CVE-2008-3522: Buffer overflow in the jas_stream_printf
    function in libjasper/base/jas_stream.c in JasPer might
    have allowed context-dependent attackers to have an
    unknown impact via vectors related to the mif_hdr_put
    function and use of vsprintf (bsc#392410)

  - jasper: NULL pointer dereference in jp2_colr_destroy
    (jp2_cod.c) (incomplete fix for CVE-2016-8887)
    (bsc#1006839) For additional change description please
    have a look at the changelog.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1005084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1005090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1005242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1006591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1006593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1006597"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1006598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1006599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1006836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1006839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1007009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/392410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/941919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942553"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2008-3522.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8158.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5203.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5221.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1577.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1867.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2089.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2116.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8690.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8691.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8692.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8693.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8880.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8881.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8882.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8883.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8884.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8885.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8886.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8887.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162775-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?881d8196"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2016-1639=1

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2016-1639=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2016-1639=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2016-1639=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2016-1639=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2016-1639=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2016-1639=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:jasper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:jasper-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjasper1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjasper1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (os_ver == "SLES12" && (! ereg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1/2", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1/2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"jasper-debuginfo-1.900.14-181.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"jasper-debugsource-1.900.14-181.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libjasper1-1.900.14-181.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libjasper1-debuginfo-1.900.14-181.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libjasper1-32bit-1.900.14-181.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libjasper1-debuginfo-32bit-1.900.14-181.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"jasper-debuginfo-1.900.14-181.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"jasper-debugsource-1.900.14-181.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libjasper1-1.900.14-181.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libjasper1-debuginfo-1.900.14-181.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libjasper1-32bit-1.900.14-181.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libjasper1-debuginfo-32bit-1.900.14-181.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"jasper-debuginfo-1.900.14-181.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"jasper-debugsource-1.900.14-181.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libjasper1-1.900.14-181.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libjasper1-32bit-1.900.14-181.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libjasper1-debuginfo-1.900.14-181.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libjasper1-debuginfo-32bit-1.900.14-181.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"jasper-debuginfo-1.900.14-181.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"jasper-debugsource-1.900.14-181.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libjasper1-1.900.14-181.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libjasper1-32bit-1.900.14-181.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libjasper1-debuginfo-1.900.14-181.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libjasper1-debuginfo-32bit-1.900.14-181.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jasper");
}
