#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:0586-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(97495);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/03/28 13:31:42 $");

  script_cve_id("CVE-2016-10046", "CVE-2016-10048", "CVE-2016-10049", "CVE-2016-10050", "CVE-2016-10051", "CVE-2016-10052", "CVE-2016-10059", "CVE-2016-10060", "CVE-2016-10063", "CVE-2016-10064", "CVE-2016-10065", "CVE-2016-10068", "CVE-2016-10070", "CVE-2016-10071", "CVE-2016-10144", "CVE-2016-10145", "CVE-2016-10146", "CVE-2016-9773", "CVE-2017-5506", "CVE-2017-5507", "CVE-2017-5508", "CVE-2017-5511");
  script_osvdb_id(134634, 134636, 139655, 142774, 142775, 142803, 142926, 143047, 146668, 147474, 149355, 149356, 149359, 149360, 149649, 149784, 150061, 150211, 150470, 150475, 150476, 150477);

  script_name(english:"SUSE SLES11 Security Update : ImageMagick (SUSE-SU-2017:0586-1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ImageMagick fixes the following issues :

  - CVE-2016-10046: Prevent buffer overflow in draw.c caused
    by an incorrect length calculation (bsc#1017308)

  - CVE-2016-10048: Arbitrary module could have been load
    because relative path were not escaped (bsc#1017310)

  - CVE-2016-10049: Corrupt RLE files could have overflowed
    a buffer due to a incorrect length calculation
    (bsc#1017311)

  - CVE-2016-10050: Corrupt RLE files could have overflowed
    a heap buffer due to a missing offset check
    (bsc#1017312)

  - CVE-2016-10051: Fixed use after free when reading PWP
    files (bsc#1017313)

  - CVE-2016-10052: Added bound check to exif parsing of
    JPEG files (bsc#1017314).

  - CVE-2016-10059: Unchecked calculation when reading TIFF
    files could have lead to a buffer overflow (bsc#1017318)

  - CVE-2016-10060: Improved error handling when writing
    files to not mask errors (bsc#1017319).

  - CVE-2016-10063: Check validity of extend during TIFF
    file reading (bsc#1017320).

  - CVE-2016-10064: Improved checks for buffer overflow when
    reading TIFF files (bsc#1017321)

  - CVE-2016-10065: Unchecked calculations when reading VIFF
    files could have lead to out of bound reads
    (bsc#1017322)

  - CVE-2016-10068: Prevent NULL pointer access when using
    the MSL interpreter (bsc#1017324)

  - CVE-2016-10070: Prevent allocating the wrong amount of
    memory when reading mat files (bsc#1017326)

  - CVE-2016-10071: Prevent allocating the wrong amount of
    memory when reading mat files (bsc#1017326).

  - CVE-2016-10144: Added a check after allocating memory
    when parsing IPL files (bsc#1020433).

  - CVE-2016-10145: Fixed of-by-one in string copy operation
    when parsing WPG files (bsc#1020435).

  - CVE-2016-10146: Captions and labels were handled
    incorrectly, causing a memory leak that could have lead
    to DoS (bsc#1020443)

  - CVE-2017-5506: Missing offset check leading to a
    double-free (bsc#1020436).

  - CVE-2017-5507: Fixed a memory leak when reading MPC
    files allowing for DoS (bsc#1020439).

  - CVE-2017-5508: Increase the amount of memory allocated
    for TIFF pixels to prevent a heap buffer-overflow
    (bsc#1020441).

  - CVE-2017-5511: A missing cast when reading PSD files
    could have caused memory corruption by a heap overflow
    (bsc#1020448) This update removes the fix for
    CVE-2016-9773. ImageMagick-6 was not affected by
    CVE-2016-9773 and it caused a regression (at least in
    GraphicsMagick) (bsc#1017421).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017310"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017324"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017326"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1017421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020433"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020441"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020443"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10046.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10048.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10049.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10050.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10051.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10052.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10059.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10060.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10063.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10064.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10065.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10068.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10070.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10071.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10144.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10145.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10146.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5506.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5507.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5508.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5511.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20170586-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98478fe9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-ImageMagick-12998=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-ImageMagick-12998=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-ImageMagick-12998=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickCore1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libMagickCore1-32bit-6.4.3.6-7.65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libMagickCore1-32bit-6.4.3.6-7.65.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libMagickCore1-6.4.3.6-7.65.1")) flag++;


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
