#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2013:1193-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83591);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_cve_id("CVE-2013-1894");

  script_name(english:"SUSE SLES10 / SLES11 Security Update : ibutils (SUSE-SU-2013:1193-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Various tmp races in ibdiagnet of ibutils have been fixed that could
have been used by local attackers on machines where infiband was
debugged to gain privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=11524c8b32981c34ce1318862678fe36
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?01a87678"
  );
  # http://download.suse.com/patch/finder/?keywords=8e5fb9360d3b7709308d0707088c7e0f
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f3e4013"
  );
  # http://download.suse.com/patch/finder/?keywords=da107ccc84270545004aae4885b15ce2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d006dcec"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1894.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/811660"
  );
  # https://www.suse.com/support/update/announcement/2013/suse-su-20131193-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a1a72da"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11 SP3 :

zypper in -t patch sdksp3-ibutils-8030

SUSE Linux Enterprise Software Development Kit 11 SP2 :

zypper in -t patch sdksp2-ibutils-8029

SUSE Linux Enterprise Server 11 SP3 for VMware :

zypper in -t patch slessp3-ibutils-8030

SUSE Linux Enterprise Server 11 SP3 :

zypper in -t patch slessp3-ibutils-8030

SUSE Linux Enterprise Server 11 SP2 for VMware :

zypper in -t patch slessp2-ibutils-8029

SUSE Linux Enterprise Server 11 SP2 :

zypper in -t patch slessp2-ibutils-8029

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ibutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ibutils-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(SLES10|SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES10 / SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^3|2$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/2", os_ver + " SP" + sp);
if (os_ver == "SLES10" && (! ereg(pattern:"^4$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"ibutils-1.5.7-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"ibutils-32bit-1.5.7-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"ibutils-1.5.7-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"ibutils-1.5.4-0.7.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"ibutils-32bit-1.5.4-0.7.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"ibutils-1.5.4-0.7.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"ibutils-1.5.4-0.13.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"ibutils-devel-1.5.4-0.13.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"ibutils-32bit-1.5.4-0.13.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"ibutils-devel-32bit-1.5.4-0.13.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"ibutils-1.5.4-0.13.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"ibutils-devel-1.5.4-0.13.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ibutils");
}
