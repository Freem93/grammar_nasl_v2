#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2667-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(94433);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/01/24 14:51:33 $");

  script_cve_id("CVE-2014-9907", "CVE-2015-8957", "CVE-2015-8958", "CVE-2015-8959", "CVE-2016-6823", "CVE-2016-7101", "CVE-2016-7513", "CVE-2016-7514", "CVE-2016-7515", "CVE-2016-7516", "CVE-2016-7517", "CVE-2016-7518", "CVE-2016-7519", "CVE-2016-7520", "CVE-2016-7521", "CVE-2016-7522", "CVE-2016-7523", "CVE-2016-7524", "CVE-2016-7525", "CVE-2016-7526", "CVE-2016-7527", "CVE-2016-7528", "CVE-2016-7529", "CVE-2016-7530", "CVE-2016-7531", "CVE-2016-7532", "CVE-2016-7533", "CVE-2016-7534", "CVE-2016-7535", "CVE-2016-7537", "CVE-2016-7538", "CVE-2016-7539", "CVE-2016-7540", "CVE-2016-7799", "CVE-2016-7800", "CVE-2016-7996", "CVE-2016-7997", "CVE-2016-8677", "CVE-2016-8682", "CVE-2016-8683", "CVE-2016-8684");
  script_osvdb_id(116915, 116919, 134466, 134467, 134469, 134470, 134471, 134473, 134474, 134475, 134476, 134478, 134480, 134481, 134482, 134484, 134485, 134486, 134489, 134490, 134492, 134635, 135625, 135813, 142338, 142846, 142859, 142860, 142880, 142923, 142933, 143042, 143613, 143614, 143615, 143616, 143617, 144991, 145002, 145319, 145326, 145389, 145393, 145394, 145395, 149321);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : ImageMagick (SUSE-SU-2016:2667-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ImageMagick fixes the following issues: These
vulnerabilities could be triggered by processing specially crafted
image files, which could lead to a process crash or resource
consumtion, or potentially have unspecified futher impact.

  - CVE-2016-8684: Mismatch between real filesize and header
    values (bsc#1005123)

  - CVE-2016-8683: Check that filesize is reasonable
    compared to the header value (bsc#1005127)

  - CVE-2016-8682: Stack-buffer read overflow while reading
    SCT header (bsc#1005125)

  - CVE-2016-8677: Memory allocation failure in
    AcquireQuantumPixels (bsc#1005328)

  - CVE-2016-7996, CVE-2016-7997: WPG Reader Issues
    (bsc#1003629)

  - CVE-2016-7800: 8BIM/8BIMW unsigned underflow leads to
    heap overflow (bsc#1002422)

  - CVE-2016-7799: mogrify global buffer overflow
    (bsc#1002421)

  - CVE-2016-7540: writing to RGF format aborts
    (bsc#1000394)

  - CVE-2016-7539: Potential DOS by not releasing memory
    (bsc#1000715)

  - CVE-2016-7538: SIGABRT for corrupted pdb file
    (bsc#1000712)

  - CVE-2016-7537: Out of bound access for corrupted pdb
    file (bsc#1000711)

  - CVE-2016-7535: Out of bound access for corrupted psd
    file (bsc#1000709)

  - CVE-2016-7534: Out of bound access in generic decoder
    (bsc#1000708)

  - CVE-2016-7533: Wpg file out of bound for corrupted file
    (bsc#1000707)

  - CVE-2016-7532: fix handling of corrupted psd file
    (bsc#1000706)

  - CVE-2016-7531: Pbd file out of bound access
    (bsc#1000704)

  - CVE-2016-7530: Out of bound in quantum handling
    (bsc#1000703)

  - CVE-2016-7529: Out-of-bound in quantum handling
    (bsc#1000399)

  - CVE-2016-7528: Out-of-bound access in xcf file coder
    (bsc#1000434)

  - CVE-2016-7527: Out-of-bound access in wpg file coder:
    (bsc#1000436)

  - CVE-2016-7526: out-of-bounds write in
    ./MagickCore/pixel-accessor.h (bsc#1000702)

  - CVE-2016-7525: Heap buffer overflow in psd file coder
    (bsc#1000701)

  - CVE-2016-7524: AddressSanitizer:heap-buffer-overflow
    READ of size 1 in meta.c:465 (bsc#1000700)

  - CVE-2016-7523: AddressSanitizer:heap-buffer-overflow
    READ of size 1 meta.c:496 (bsc#1000699)

  - CVE-2016-7522: Out of bound access for malformed psd
    file (bsc#1000698)

  - CVE-2016-7521: Heap buffer overflow in psd file handling
    (bsc#1000697)

  - CVE-2016-7520: Heap overflow in hdr file handling
    (bsc#1000696)

  - CVE-2016-7519: Out-of-bounds read in coders/rle.c
    (bsc#1000695)

  - CVE-2016-7518: Out-of-bounds read in coders/sun.c
    (bsc#1000694)

  - CVE-2016-7517: Out-of-bounds read in coders/pict.c
    (bsc#1000693)

  - CVE-2016-7516: Out-of-bounds problem in rle, pict, viff
    and sun files (bsc#1000692)

  - CVE-2016-7515: Rle file handling for corrupted file
    (bsc#1000689)

  - CVE-2016-7514: Out-of-bounds read in coders/psd.c
    (bsc#1000688)

  - CVE-2016-7513: Off-by-one error leading to segfault
    (bsc#1000686)

  - CVE-2016-7101: raphicsMagick: SGI Coder Out-Of-Bounds
    Read Vulnerability (bsc#1001221)

  - CVE-2016-6823: raphicsMagick: BMP Coder Out-Of-Bounds
    Write Vulnerability (bsc#1001066)

  - CVE-2015-8959: dOS due to corrupted DDS files
    (bsc#1000713)

  - CVE-2015-8958: Potential DOS in sun file handling due to
    malformed files (bsc#1000691)

  - CVE-2015-8957: Buffer overflow in sun file handling
    (bsc#1000690)

  - CVE-2014-9907: DOS due to corrupted DDS files
    (bsc#1000714)

  - Buffer overflows in SIXEL, PDB, MAP, and TIFF coders
    (bsc#1002209)

  - Divide by zero in WriteTIFFImage (bsc#1002206)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000702"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000704"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000707"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000714"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1001066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1001221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1002206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1002209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1002421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1002422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1005123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1005125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1005127"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1005328"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9907.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8957.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8958.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8959.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6823.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7101.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7513.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7514.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7515.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7516.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7517.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7518.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7519.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7520.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7521.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7522.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7523.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7524.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7525.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7526.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7527.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7528.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7529.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7530.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7531.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7532.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7533.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7534.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7535.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7537.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7538.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7539.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7540.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7799.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7800.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7996.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7997.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8677.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8682.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8683.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8684.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162667-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f1725192"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP1:zypper in -t patch
SUSE-SLE-WE-12-SP1-2016-1572=1

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2016-1572=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2016-1572=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2016-1572=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ImageMagick-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagick++-6_Q16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagick++-6_Q16-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickCore-6_Q16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickCore-6_Q16-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickCore-6_Q16-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickWand-6_Q16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickWand-6_Q16-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/31");
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
if (os_ver == "SLES12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"ImageMagick-debuginfo-6.8.8.1-40.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"ImageMagick-debugsource-6.8.8.1-40.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libMagickCore-6_Q16-1-6.8.8.1-40.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libMagickCore-6_Q16-1-debuginfo-6.8.8.1-40.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libMagickWand-6_Q16-1-6.8.8.1-40.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libMagickWand-6_Q16-1-debuginfo-6.8.8.1-40.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"ImageMagick-6.8.8.1-40.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"ImageMagick-debuginfo-6.8.8.1-40.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"ImageMagick-debugsource-6.8.8.1-40.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libMagick++-6_Q16-3-6.8.8.1-40.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libMagick++-6_Q16-3-debuginfo-6.8.8.1-40.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-32bit-6.8.8.1-40.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-6.8.8.1-40.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-debuginfo-32bit-6.8.8.1-40.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libMagickCore-6_Q16-1-debuginfo-6.8.8.1-40.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-6.8.8.1-40.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libMagickWand-6_Q16-1-debuginfo-6.8.8.1-40.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick");
}
