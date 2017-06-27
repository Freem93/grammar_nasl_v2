#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:1041-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(99463);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/19 13:27:09 $");

  script_cve_id("CVE-2017-5837", "CVE-2017-5839", "CVE-2017-5842", "CVE-2017-5844");
  script_osvdb_id(151267, 151336, 151337);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : gstreamer-plugins-base (SUSE-SU-2017:1041-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gstreamer-plugins-base fixes the following security
issues :

  - A crafted AVI file could have caused a floating point
    exception leading to DoS (bsc#1024076, CVE-2017-5837,
    bsc#1024079, CVE-2017-5844)

  - A crafted AVI file could have caused a stack overflow
    leading to DoS (bsc#1024047, CVE-2017-5839)

  - A crafted SAMI subtitle file could have caused an
    invalid memory access possibly leading to DoS or
    corruption (bsc#1024041, CVE-2017-5842)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1024041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1024047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1024076"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1024079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5837.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5839.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5842.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5844.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20171041-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb4a9b60"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP1:zypper in -t patch
SUSE-SLE-WE-12-SP1-2017-606=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2017-606=1

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2017-606=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2017-606=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2017-606=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gstreamer-plugins-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gstreamer-plugins-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gstreamer-plugins-base-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstallocators-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstallocators-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstapp-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstapp-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstapp-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstaudio-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstaudio-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstaudio-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstfft-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstfft-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstfft-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstpbutils-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstpbutils-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstpbutils-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstriff-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstriff-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstrtp-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstrtp-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstrtsp-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstrtsp-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstsdp-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstsdp-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgsttag-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgsttag-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgsttag-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstvideo-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstvideo-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstvideo-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-GstAudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-GstPbutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-GstTag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-GstVideo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/19");
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
if (rpm_check(release:"SLES12", sp:"1", reference:"gstreamer-plugins-base-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"gstreamer-plugins-base-debuginfo-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"gstreamer-plugins-base-debugsource-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstallocators-1_0-0-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstallocators-1_0-0-debuginfo-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstapp-1_0-0-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstapp-1_0-0-debuginfo-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstaudio-1_0-0-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstaudio-1_0-0-debuginfo-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstfft-1_0-0-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstfft-1_0-0-debuginfo-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstpbutils-1_0-0-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstpbutils-1_0-0-debuginfo-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstriff-1_0-0-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstriff-1_0-0-debuginfo-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstrtp-1_0-0-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstrtp-1_0-0-debuginfo-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstrtsp-1_0-0-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstrtsp-1_0-0-debuginfo-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstsdp-1_0-0-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstsdp-1_0-0-debuginfo-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgsttag-1_0-0-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgsttag-1_0-0-debuginfo-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstvideo-1_0-0-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstvideo-1_0-0-debuginfo-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"gstreamer-plugins-base-debuginfo-32bit-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstapp-1_0-0-32bit-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstapp-1_0-0-debuginfo-32bit-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstaudio-1_0-0-32bit-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstaudio-1_0-0-debuginfo-32bit-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstpbutils-1_0-0-32bit-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstpbutils-1_0-0-debuginfo-32bit-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgsttag-1_0-0-32bit-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgsttag-1_0-0-debuginfo-32bit-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstvideo-1_0-0-32bit-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgstvideo-1_0-0-debuginfo-32bit-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"gstreamer-plugins-base-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"gstreamer-plugins-base-debuginfo-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"gstreamer-plugins-base-debuginfo-32bit-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"gstreamer-plugins-base-debugsource-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstallocators-1_0-0-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstallocators-1_0-0-debuginfo-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstapp-1_0-0-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstapp-1_0-0-32bit-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstapp-1_0-0-debuginfo-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstapp-1_0-0-debuginfo-32bit-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstaudio-1_0-0-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstaudio-1_0-0-32bit-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstaudio-1_0-0-debuginfo-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstaudio-1_0-0-debuginfo-32bit-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstfft-1_0-0-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstfft-1_0-0-32bit-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstfft-1_0-0-debuginfo-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstfft-1_0-0-debuginfo-32bit-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstpbutils-1_0-0-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstpbutils-1_0-0-32bit-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstpbutils-1_0-0-debuginfo-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstpbutils-1_0-0-debuginfo-32bit-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstriff-1_0-0-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstriff-1_0-0-debuginfo-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstrtp-1_0-0-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstrtp-1_0-0-debuginfo-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstrtsp-1_0-0-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstrtsp-1_0-0-debuginfo-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstsdp-1_0-0-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstsdp-1_0-0-debuginfo-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgsttag-1_0-0-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgsttag-1_0-0-32bit-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgsttag-1_0-0-debuginfo-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgsttag-1_0-0-debuginfo-32bit-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstvideo-1_0-0-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstvideo-1_0-0-32bit-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstvideo-1_0-0-debuginfo-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstvideo-1_0-0-debuginfo-32bit-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"typelib-1_0-GstAudio-1_0-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"typelib-1_0-GstPbutils-1_0-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"typelib-1_0-GstTag-1_0-1.2.4-2.6.8")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"typelib-1_0-GstVideo-1_0-1.2.4-2.6.8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gstreamer-plugins-base");
}
