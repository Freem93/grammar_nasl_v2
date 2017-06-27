#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:0331-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(96902);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/01/31 14:53:43 $");

  script_cve_id("CVE-2016-9809");
  script_osvdb_id(147996);

  script_name(english:"SUSE SLED12 Security Update : gstreamer-0_10-plugins-bad (SUSE-SU-2017:0331-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"gstreamer-0_10-plugins-bad was udpated to fix one issue. This security
issue was fixed :

  - CVE-2016-9809: Off by one read in
    gst_h264_parse_set_caps() (bsc#1013659).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9809.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20170331-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?36e0bbf1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP1:zypper in -t patch
SUSE-SLE-WE-12-SP1-2017-166=1

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2017-166=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2017-166=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gstreamer-0_10-plugins-bad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gstreamer-0_10-plugins-bad-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gstreamer-0_10-plugins-bad-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstbasecamerabinsrc-0_10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstbasecamerabinsrc-0_10-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstbasecamerabinsrc-0_10-23-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstbasevideo-0_10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstbasevideo-0_10-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstbasevideo-0_10-23-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstcodecparsers-0_10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstcodecparsers-0_10-23-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstphotography-0_10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstphotography-0_10-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstphotography-0_10-23-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstsignalprocessor-0_10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstsignalprocessor-0_10-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstsignalprocessor-0_10-23-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstvdp-0_10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstvdp-0_10-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgstvdp-0_10-23-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/31");
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
if (! ereg(pattern:"^(SLED12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"gstreamer-0_10-plugins-bad-0.10.23-19.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"gstreamer-0_10-plugins-bad-debuginfo-0.10.23-19.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"gstreamer-0_10-plugins-bad-debuginfo-32bit-0.10.23-19.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"gstreamer-0_10-plugins-bad-debugsource-0.10.23-19.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstbasecamerabinsrc-0_10-23-0.10.23-19.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstbasecamerabinsrc-0_10-23-32bit-0.10.23-19.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstbasecamerabinsrc-0_10-23-debuginfo-0.10.23-19.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstbasecamerabinsrc-0_10-23-debuginfo-32bit-0.10.23-19.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstbasevideo-0_10-23-0.10.23-19.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstbasevideo-0_10-23-32bit-0.10.23-19.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstbasevideo-0_10-23-debuginfo-0.10.23-19.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstbasevideo-0_10-23-debuginfo-32bit-0.10.23-19.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstcodecparsers-0_10-23-0.10.23-19.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstcodecparsers-0_10-23-debuginfo-0.10.23-19.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstphotography-0_10-23-0.10.23-19.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstphotography-0_10-23-32bit-0.10.23-19.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstphotography-0_10-23-debuginfo-0.10.23-19.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstphotography-0_10-23-debuginfo-32bit-0.10.23-19.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstsignalprocessor-0_10-23-0.10.23-19.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstsignalprocessor-0_10-23-32bit-0.10.23-19.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstsignalprocessor-0_10-23-debuginfo-0.10.23-19.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstsignalprocessor-0_10-23-debuginfo-32bit-0.10.23-19.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstvdp-0_10-23-0.10.23-19.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstvdp-0_10-23-32bit-0.10.23-19.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstvdp-0_10-23-debuginfo-0.10.23-19.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgstvdp-0_10-23-debuginfo-32bit-0.10.23-19.6.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gstreamer-0_10-plugins-bad");
}
