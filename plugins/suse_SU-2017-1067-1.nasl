#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:1067-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(99578);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/03 13:42:51 $");

  script_cve_id("CVE-2014-4975", "CVE-2015-1855", "CVE-2015-3900", "CVE-2015-7551", "CVE-2016-2339");
  script_bugtraq_id(68474, 74446, 75482);
  script_osvdb_id(108971, 120541, 122162, 131943, 140169);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : ruby2.1 (SUSE-SU-2017:1067-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This ruby2.1 update to version 2.1.9 fixes the following issues:
Security issues fixed :

  - CVE-2016-2339: heap overflow vulnerability in the
    Fiddle::Function.new'initialize' (bsc#1018808)

  - CVE-2015-7551: Unsafe tainted string usage in Fiddle and
    DL (bsc#959495)

  - CVE-2015-3900: hostname validation does not work when
    fetching gems or making API requests (bsc#936032)

  - CVE-2015-1855: Ruby'a OpenSSL extension suffers a
    vulnerability through overly permissive matching of
    hostnames (bsc#926974)

  - CVE-2014-4975: off-by-one stack-based buffer overflow in
    the encodes() function (bsc#887877) Bugfixes :

  - SUSEconnect doesn't handle domain wildcards in no_proxy
    environment variable properly (bsc#1014863)

  - Segmentation fault after pack & ioctl & unpack
    (bsc#909695)

  - Ruby:HTTP Header injection in 'net/http' (bsc#986630)
    ChangeLog :

- http://svn.ruby-lang.org/repos/ruby/tags/v2_1_9/ChangeLog

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://svn.ruby-lang.org/repos/ruby/tags/v2_1_9/ChangeLog"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1014863"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1018808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/887877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/909695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/926974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-4975.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1855.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3900.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7551.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2339.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20171067-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2614ef7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2017-624=1

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2017-624=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-624=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-624=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2017-624=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-624=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2017-624=1

OpenStack Cloud Magnum Orchestration 7:zypper in -t patch
SUSE-OpenStack-Cloud-Magnum-Orchestration-7-2017-624=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libruby2_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libruby2_1-2_1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby2.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby2.1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby2.1-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby2.1-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby2.1-stdlib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/21");
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
if (os_ver == "SLES12" && (! ereg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1/2", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1/2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"libruby2_1-2_1-2.1.9-15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libruby2_1-2_1-debuginfo-2.1.9-15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"ruby2.1-2.1.9-15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"ruby2.1-debuginfo-2.1.9-15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"ruby2.1-debugsource-2.1.9-15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"ruby2.1-stdlib-2.1.9-15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"ruby2.1-stdlib-debuginfo-2.1.9-15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libruby2_1-2_1-2.1.9-15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libruby2_1-2_1-debuginfo-2.1.9-15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"ruby2.1-2.1.9-15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"ruby2.1-debuginfo-2.1.9-15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"ruby2.1-debugsource-2.1.9-15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"ruby2.1-stdlib-2.1.9-15.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"ruby2.1-stdlib-debuginfo-2.1.9-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libruby2_1-2_1-2.1.9-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libruby2_1-2_1-debuginfo-2.1.9-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"ruby2.1-2.1.9-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"ruby2.1-debuginfo-2.1.9-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"ruby2.1-debugsource-2.1.9-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"ruby2.1-stdlib-2.1.9-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"ruby2.1-stdlib-debuginfo-2.1.9-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libruby2_1-2_1-2.1.9-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libruby2_1-2_1-debuginfo-2.1.9-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"ruby2.1-2.1.9-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"ruby2.1-debuginfo-2.1.9-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"ruby2.1-debugsource-2.1.9-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"ruby2.1-stdlib-2.1.9-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"ruby2.1-stdlib-debuginfo-2.1.9-15.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby2.1");
}
