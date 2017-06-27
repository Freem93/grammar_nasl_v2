#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2106-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93300);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2016-0772", "CVE-2016-1000110", "CVE-2016-5636", "CVE-2016-5699");
  script_osvdb_id(115884, 140038, 140125, 141671);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : python (SUSE-SU-2016:2106-1) (httpoxy)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for python fixes the following issues :

  - CVE-2016-0772: smtplib vulnerability opens startTLS
    stripping attack (bsc#984751)

  - CVE-2016-5636: heap overflow when importing malformed
    zip files (bsc#985177)

  - CVE-2016-5699: incorrect validation of HTTP headers
    allow header injection (bsc#985348)

  - CVE-2016-1000110: HTTPoxy vulnerability in urllib, fixed
    by disregarding HTTP_PROXY when REQUEST_METHOD is also
    set (bsc#989523)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984751"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0772.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1000110.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5636.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5699.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162106-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?be724e01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP1:zypper in -t patch
SUSE-SLE-WE-12-SP1-2016-1245=1

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2016-1245=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2016-1245=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2016-1245=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpython2_7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpython2_7-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpython2_7-1_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-base-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-curses-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-gdbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-gdbm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-tk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-xml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/19");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/02");
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
if (rpm_check(release:"SLES12", sp:"1", reference:"libpython2_7-1_0-2.7.9-24.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libpython2_7-1_0-debuginfo-2.7.9-24.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-2.7.9-24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-base-2.7.9-24.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-base-debuginfo-2.7.9-24.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-base-debugsource-2.7.9-24.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-curses-2.7.9-24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-curses-debuginfo-2.7.9-24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-debuginfo-2.7.9-24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-debugsource-2.7.9-24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-demo-2.7.9-24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-gdbm-2.7.9-24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-gdbm-debuginfo-2.7.9-24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-idle-2.7.9-24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-tk-2.7.9-24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-tk-debuginfo-2.7.9-24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-xml-2.7.9-24.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-xml-debuginfo-2.7.9-24.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libpython2_7-1_0-32bit-2.7.9-24.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libpython2_7-1_0-debuginfo-32bit-2.7.9-24.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-32bit-2.7.9-24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-base-32bit-2.7.9-24.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-base-debuginfo-32bit-2.7.9-24.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-debuginfo-32bit-2.7.9-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libpython2_7-1_0-2.7.9-24.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libpython2_7-1_0-32bit-2.7.9-24.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libpython2_7-1_0-debuginfo-2.7.9-24.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libpython2_7-1_0-debuginfo-32bit-2.7.9-24.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"python-2.7.9-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"python-base-2.7.9-24.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"python-base-debuginfo-2.7.9-24.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"python-base-debuginfo-32bit-2.7.9-24.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"python-base-debugsource-2.7.9-24.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"python-curses-2.7.9-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"python-curses-debuginfo-2.7.9-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"python-debuginfo-2.7.9-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"python-debugsource-2.7.9-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"python-devel-2.7.9-24.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"python-tk-2.7.9-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"python-tk-debuginfo-2.7.9-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"python-xml-2.7.9-24.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"python-xml-debuginfo-2.7.9-24.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python");
}
