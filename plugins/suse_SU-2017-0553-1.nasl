#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:0553-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(97380);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/04/18 13:37:18 $");

  script_cve_id("CVE-2016-5011", "CVE-2017-2616");
  script_osvdb_id(141270, 152469);

  script_name(english:"SUSE SLES12 Security Update : util-linux (SUSE-SU-2017:0553-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for util-linux fixes a number of bugs and two security
issues. The following security bugs were fixed :

  - CVE-2016-5011: Infinite loop DoS in libblkid while
    parsing DOS partition (bsc#988361)

  - CVE-2017-2616: In su with PAM support it was possible
    for local users to send SIGKILL to selected other
    processes with root privileges (bsc#1023041). The
    following non-security bugs were fixed :

  - bsc#1008965: Ensure that the option
    'users,exec,dev,suid' work as expected on NFS mounts

  - bsc#1012504: Fix regressions in safe loop re-use patch
    set for libmount

  - bsc#1012632: Disable ro checks for mtab

  - bsc#1020077: fstrim: De-duplicate btrfs sub-volumes for
    'fstrim -a' and bind mounts

  - bsc#947494: mount -a would fail to recognize btrfs
    already mounted, address loop re-use in libmount

  - bsc#966891: Conflict in meaning of losetup -L. This
    switch in SLE12 SP1 and SP2 continues to carry the
    meaning of --logical-blocksize instead of upstream
    --nooverlap

  - bsc#978993: cfdisk would mangle some text output

  - bsc#982331: libmount: ignore redundant slashes

  - bsc#983164: mount uid= and gid= would reject valid non
    UID/GID values

  - bsc#987176: When mounting a subfolder of a CIFS share,
    mount -a would show the mount as busy

  - bsc#1019332: lscpu: Implement WSL detection and work
    around crash

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1008965"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1019332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1020077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1023041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/947494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982331"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/988361"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5011.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2616.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20170553-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?55ba9821"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 12:zypper in -t patch
SUSE-SLE-SAP-12-2017-290=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2017-290=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libblkid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libblkid1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmount1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmount1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmartcols1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmartcols1-debuginfo");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/24");
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
if (! ereg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"libblkid1-2.25-24.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libblkid1-debuginfo-2.25-24.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmount1-2.25-24.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmount1-debuginfo-2.25-24.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmartcols1-2.25-24.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmartcols1-debuginfo-2.25-24.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libuuid1-2.25-24.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libuuid1-debuginfo-2.25-24.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"python-libmount-2.25-24.10.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"python-libmount-debuginfo-2.25-24.10.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"python-libmount-debugsource-2.25-24.10.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"util-linux-2.25-24.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"util-linux-debuginfo-2.25-24.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"util-linux-debugsource-2.25-24.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"util-linux-systemd-2.25-24.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"util-linux-systemd-debuginfo-2.25-24.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"util-linux-systemd-debugsource-2.25-24.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"uuidd-2.25-24.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"uuidd-debuginfo-2.25-24.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libblkid1-32bit-2.25-24.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libblkid1-debuginfo-32bit-2.25-24.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmount1-32bit-2.25-24.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmount1-debuginfo-32bit-2.25-24.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libuuid1-32bit-2.25-24.10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libuuid1-debuginfo-32bit-2.25-24.10.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "util-linux");
}
