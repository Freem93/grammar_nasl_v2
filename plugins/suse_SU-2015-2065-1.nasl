#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:2065-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(87051);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/02 15:19:32 $");

  script_cve_id("CVE-2015-0794");
  script_osvdb_id(130498);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : dracut (SUSE-SU-2015:2065-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The dracut package was updated to fix the following security and
non-security issues :

  - CVE-2015-0794: Use mktemp instead of hard-coded
    filenames, possible vulnerability (bsc#935338).

  - Always install mdraid modules (bsc#935993).

  - Add notice when dracut failed to install modules
    (bsc#952491).

  - Always install dm-snaphost module if lvm dracut module
    is needed, even if dm-snapshot is not loaded on the host
    yet (bsc#947518).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/947518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/952491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0794.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20152065-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?defee4f3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-877=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-877=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dracut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dracut-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dracut-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dracut-fips");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES12", sp:"0", reference:"dracut-037-51.17.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"dracut-debuginfo-037-51.17.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"dracut-debugsource-037-51.17.3")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"dracut-fips-037-51.17.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"dracut-037-51.17.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"dracut-debuginfo-037-51.17.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"dracut-debugsource-037-51.17.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dracut");
}
