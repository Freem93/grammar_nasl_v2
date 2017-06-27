#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2653-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(94321);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/12/27 20:24:10 $");

  script_cve_id("CVE-2016-0772", "CVE-2016-1000110", "CVE-2016-5636", "CVE-2016-5699");
  script_osvdb_id(115884, 140038, 140125, 141671);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : python3 (SUSE-SU-2016:2653-1) (httpoxy)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update provides Python 3.4.5, which brings many fixes and
enhancements. The following security issues have been fixed :

  - CVE-2016-1000110: CGIHandler could have allowed setting
    of HTTP_PROXY environment variable based on
    user-supplied Proxy request header. (bsc#989523)

  - CVE-2016-0772: A vulnerability in smtplib could have
    allowed a MITM attacker to perform a startTLS stripping
    attack. (bsc#984751)

  - CVE-2016-5636: A heap overflow in Python's zipimport
    module. (bsc#985177)

  - CVE-2016-5699: A header injection flaw in
    urrlib2/urllib/httplib/http.client. (bsc#985348) The
    update also includes the following non-security fixes :

  - Don't force 3rd party C extensions to be built with

    -Werror=declaration-after-statement. (bsc#951166)

  - Make urllib proxy var handling behave as usual on POSIX.
    (bsc#983582) For a comprehensive list of changes please
    refer to the upstream change log:
    https://docs.python.org/3.4/whatsnew/changelog.html

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983582"
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
    value:"https://bugzilla.suse.com/991069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.python.org/3.4/whatsnew/changelog.html"
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
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162653-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?252dd025"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2016-1558=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2016-1558=1

SUSE Linux Enterprise Module for Web Scripting 12:zypper in -t patch
SUSE-SLE-Module-Web-Scripting-12-2016-1558=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2016-1558=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpython3_4m1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpython3_4m1_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-base-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/26");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/27");
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
if (rpm_check(release:"SLES12", sp:"1", reference:"libpython3_4m1_0-3.4.5-17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libpython3_4m1_0-debuginfo-3.4.5-17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python3-3.4.5-17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python3-base-3.4.5-17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python3-base-debuginfo-3.4.5-17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python3-base-debugsource-3.4.5-17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python3-debuginfo-3.4.5-17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python3-debugsource-3.4.5-17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libpython3_4m1_0-3.4.5-17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libpython3_4m1_0-debuginfo-3.4.5-17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"python3-3.4.5-17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"python3-base-3.4.5-17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"python3-base-debuginfo-3.4.5-17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"python3-base-debugsource-3.4.5-17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"python3-debuginfo-3.4.5-17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"python3-debugsource-3.4.5-17.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python3");
}
