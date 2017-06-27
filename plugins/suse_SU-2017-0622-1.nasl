#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:0622-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(97598);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/08 15:07:21 $");

  script_cve_id("CVE-2016-10207", "CVE-2016-9941", "CVE-2016-9942");
  script_osvdb_id(149427, 149428, 151448);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : tigervnc (SUSE-SU-2017:0622-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for tigervnc provides the following fixes :

  - Prevent malicious server from crashing a server via a
    buffer overflow, a similar flaw as the LibVNCServer
    issues CVE-2016-9941 and CVE-2016-9942. (bsc#1019274)

  - CVE-2016-10207: Prevent potential crash due to
    insufficient clean-up after failure to establish TLS
    connection. (bsc#1023012)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019274"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1023012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10207.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9941.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9942.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20170622-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?38d975dd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-335=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-335=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-335=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libXvnc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libXvnc1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tigervnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tigervnc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tigervnc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xorg-x11-Xvnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xorg-x11-Xvnc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/08");
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
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXvnc1-1.6.0-16.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXvnc1-debuginfo-1.6.0-16.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"tigervnc-1.6.0-16.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"tigervnc-debuginfo-1.6.0-16.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"tigervnc-debugsource-1.6.0-16.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"xorg-x11-Xvnc-1.6.0-16.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"xorg-x11-Xvnc-debuginfo-1.6.0-16.4")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXvnc1-1.6.0-16.4")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXvnc1-debuginfo-1.6.0-16.4")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"tigervnc-1.6.0-16.4")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"tigervnc-debuginfo-1.6.0-16.4")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"tigervnc-debugsource-1.6.0-16.4")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"xorg-x11-Xvnc-1.6.0-16.4")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"xorg-x11-Xvnc-debuginfo-1.6.0-16.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tigervnc");
}
