#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:0302-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(96868);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/01/30 15:10:04 $");

  script_cve_id("CVE-2016-0634", "CVE-2016-7543");
  script_osvdb_id(144525, 144718);

  script_name(english:"SUSE SLES11 Security Update : bash (SUSE-SU-2017:0302-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for bash fixes the following issues :

  - CVE-2016-7543: Local attackers could have executed
    arbitrary commands via specially crafted SHELLOPTS+PS4
    variables. (bsc#1001299)

  - CVE-2016-0634: Malicious hostnames could have allowed
    arbitrary command execution when $HOSTNAME was expanded
    in the prompt. (bsc#1000396) The following bugs were
    fixed :

  - bsc#971410: Scripts could terminate unexpectedly due to
    mishandled recursive traps.

  - bsc#959755: Clarify that the files /etc/profile as well
    as /etc/bash.bashrc may source other files as well even
    if the bash does not.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000396"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1001299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0634.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7543.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20170302-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd76614e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-bash-12959=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-bash-12959=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-bash-12959=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bash-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreadline5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:readline-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/30");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libreadline5-32bit-5.2-147.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libreadline5-32bit-5.2-147.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"bash-3.2-147.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"bash-doc-3.2-147.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libreadline5-5.2-147.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"readline-doc-5.2-147.29.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bash");
}
