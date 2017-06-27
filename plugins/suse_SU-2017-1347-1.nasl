#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:1347-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(100351);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/23 14:39:44 $");

  script_cve_id("CVE-2017-7470");
  script_osvdb_id(157812);

  script_name(english:"SUSE SLES11 Security Update : SUSE Manager Client Tools (SUSE-SU-2017:1347-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following security issue in spacewalk-backend has been fixed :

  - Non admin or disabled user cannot make changes to a
    system anymore using spacewalk-channel. (bsc#1026633,
    CVE-2017-7470) Additionally, the following non-security
    issues have been fixed: rhnlib :

  - Support all TLS versions in rpclib. (bsc#1025312)
    spacecmd :

  - Improve output on error for listrepo. (bsc#1027426)

  - Reword spacecmd removal message. (bsc#1024406)
    spacewalk-backend :

  - Do not fail with traceback when media.1 does not exist.
    (bsc#1032256)

  - Create scap files directory beforehand. (bsc#1029755)

  - Fix error if SPACEWALK_DEBUG_NO_REPORTS environment
    variable is not present.

  - Don't skip 'rhnErrataPackage' cleanup during an errata
    update. (bsc#1023233)

  - Add support for running spacewalk-debug without creating
    reports. (bsc#1024714)

  - Set scap store directory mod to 775 and group owner to
    susemanager.

  - incomplete_package_import: Do import rhnPackageFile as
    it breaks some package installations.

  - Added traceback printing to the exception block.

  - Change postgresql starting commands.
    spacewalk-client-tools :

  - Fix reboot message to use correct product name.
    (bsc#1031667)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1023233"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1024406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1024714"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1025312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1026633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1027426"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1029755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1031667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1032256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7470.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20171347-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c80889b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP4-CLIENT-TOOLS:zypper in -t patch
slesctsp4-client-tools-201704-13115=1

SUSE Linux Enterprise Server 11-SP3-CLIENT-TOOLS:zypper in -t patch
slesctsp3-client-tools-201704-13115=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rhnlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacecmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-backend-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/23");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"rhnlib-2.5.84.4-8.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"spacecmd-2.5.5.5-14.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"spacewalk-backend-libs-2.5.24.9-24.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"rhnlib-2.5.84.4-8.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"spacecmd-2.5.5.5-14.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"spacewalk-backend-libs-2.5.24.9-24.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "SUSE Manager Client Tools");
}
