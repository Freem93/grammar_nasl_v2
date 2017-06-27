#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0805-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83722);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/04/05 21:24:25 $");

  script_cve_id("CVE-2015-2265");
  script_bugtraq_id(73008);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : cups-filters (SUSE-SU-2015:0805-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"cups-filters was updated to fix one security issue.

This security issue was fixed :

  - CVE-2015-2265: Remote command execution in
    remove_bad_chars() (bnc#921753).

This non-security issue was fixed :

  - LSB compliance of foomatic-rip (bnc#915545).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/921753"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2265.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150805-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8b68324a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-177=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-177=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-filters-cups-browsed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-filters-cups-browsed-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-filters-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-filters-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-filters-foomatic-rip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-filters-foomatic-rip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-filters-ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-filters-ghostscript-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
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
if (rpm_check(release:"SLES12", sp:"0", reference:"cups-filters-1.0.58-5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"cups-filters-cups-browsed-1.0.58-5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"cups-filters-cups-browsed-debuginfo-1.0.58-5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"cups-filters-debuginfo-1.0.58-5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"cups-filters-debugsource-1.0.58-5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"cups-filters-foomatic-rip-1.0.58-5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"cups-filters-foomatic-rip-debuginfo-1.0.58-5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"cups-filters-ghostscript-1.0.58-5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"cups-filters-ghostscript-debuginfo-1.0.58-5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"cups-filters-1.0.58-5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"cups-filters-cups-browsed-1.0.58-5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"cups-filters-cups-browsed-debuginfo-1.0.58-5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"cups-filters-debuginfo-1.0.58-5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"cups-filters-debugsource-1.0.58-5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"cups-filters-foomatic-rip-1.0.58-5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"cups-filters-foomatic-rip-debuginfo-1.0.58-5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"cups-filters-ghostscript-1.0.58-5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"cups-filters-ghostscript-debuginfo-1.0.58-5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups-filters");
}
