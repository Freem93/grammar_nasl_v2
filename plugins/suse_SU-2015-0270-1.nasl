#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0270-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83679);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/04/06 13:23:47 $");

  script_cve_id("CVE-2014-9114");
  script_bugtraq_id(71327);
  script_osvdb_id(115162);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : util-linux (SUSE-SU-2015:0270-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"util-linux was updated to fix one security issue.

This security issue was fixed :

  - CVE-2014-9114: Using crafted block devices (e.g. USB
    sticks) it was possibly to inject code via libblkid.
    libblkid was fixed to care about unsafe chars and
    possible buffer overflow in cache (bnc#907434)

This non-security issue was fixed :

  - libblkid: Reset errno in blkid_probe_get_buffer() to
    prevent failing probes (e. g. for exFAT) (bnc#908742).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9114.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=907434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=908742"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150270-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5c1b797"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12 :

zypper in -t patch SUSE-SLE-WE-12-2015-67=1

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-67=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-67=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-67=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libblkid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libblkid1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmount1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmount1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmartcols1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmartcols1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libuuid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libuuid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libuuid1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-libmount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-libmount-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-libmount-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:util-linux-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:util-linux-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:util-linux-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:util-linux-systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:util-linux-systemd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:uuidd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:uuidd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES12", sp:"0", reference:"libblkid1-2.25-10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libblkid1-debuginfo-2.25-10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmount1-2.25-10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmount1-debuginfo-2.25-10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmartcols1-2.25-10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmartcols1-debuginfo-2.25-10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libuuid1-2.25-10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libuuid1-debuginfo-2.25-10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"python-libmount-2.25-10.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"python-libmount-debuginfo-2.25-10.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"python-libmount-debugsource-2.25-10.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"util-linux-2.25-10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"util-linux-debuginfo-2.25-10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"util-linux-debugsource-2.25-10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"util-linux-systemd-2.25-10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"util-linux-systemd-debuginfo-2.25-10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"util-linux-systemd-debugsource-2.25-10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"uuidd-2.25-10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"uuidd-debuginfo-2.25-10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libblkid1-32bit-2.25-10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libblkid1-debuginfo-32bit-2.25-10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmount1-32bit-2.25-10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmount1-debuginfo-32bit-2.25-10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libuuid1-32bit-2.25-10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libuuid1-debuginfo-32bit-2.25-10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libblkid1-2.25-10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libblkid1-32bit-2.25-10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libblkid1-debuginfo-2.25-10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libblkid1-debuginfo-32bit-2.25-10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmount1-2.25-10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmount1-32bit-2.25-10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmount1-debuginfo-2.25-10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmount1-debuginfo-32bit-2.25-10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmartcols1-2.25-10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libsmartcols1-debuginfo-2.25-10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libuuid-devel-2.25-10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libuuid1-2.25-10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libuuid1-32bit-2.25-10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libuuid1-debuginfo-2.25-10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libuuid1-debuginfo-32bit-2.25-10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"python-libmount-2.25-10.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"python-libmount-debuginfo-2.25-10.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"python-libmount-debugsource-2.25-10.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"util-linux-2.25-10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"util-linux-debuginfo-2.25-10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"util-linux-debugsource-2.25-10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"util-linux-systemd-2.25-10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"util-linux-systemd-debuginfo-2.25-10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"util-linux-systemd-debugsource-2.25-10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"uuidd-2.25-10.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"uuidd-debuginfo-2.25-10.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "util-linux");
}
