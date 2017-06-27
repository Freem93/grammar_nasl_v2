#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2014:0732-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83625);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/11/02 15:20:57 $");

  script_cve_id("CVE-2013-6629", "CVE-2014-0429", "CVE-2014-0446", "CVE-2014-0451", "CVE-2014-0453", "CVE-2014-0457", "CVE-2014-0460", "CVE-2014-0878", "CVE-2014-1876", "CVE-2014-2398", "CVE-2014-2401", "CVE-2014-2412", "CVE-2014-2421", "CVE-2014-2427");
  script_bugtraq_id(63676, 65568, 66856, 66866, 66873, 66879, 66881, 66903, 66909, 66911, 66914, 66916, 66920, 67601);

  script_name(english:"SUSE SLES10 Security Update : IBM Java 5 (SUSE-SU-2014:0732-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IBM Java 5 was updated to SR 16 FP 6 to fix several bugs and security
issues.

Further information is available at:
https://www.ibm.com/developerworks/java/jdk/aix/j532/fixes.html#SR16FP
6

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=29c5cf97cb2a3ebfac90cfacae2c711e
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b89043c4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6629.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0429.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0446.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0451.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0453.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0457.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0460.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0878.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1876.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-2398.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-2401.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-2412.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-2421.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-2427.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/878654"
  );
  # https://www.ibm.com/developerworks/java/jdk/aix/j532/fixes.html#SR16FP6
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6cde7c80"
  );
  # https://www.suse.com/support/update/announcement/2014/suse-su-20140732-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ae7f49dd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected IBM Java 5 packages"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_5_0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_5_0-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_5_0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_5_0-ibm-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_5_0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_5_0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/29");
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
if (! ereg(pattern:"^(SLES10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES10" && (! ereg(pattern:"^3$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"java-1_5_0-ibm-32bit-1.5.0_sr16.6-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"java-1_5_0-ibm-devel-32bit-1.5.0_sr16.6-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"java-1_5_0-ibm-alsa-32bit-1.5.0_sr16.6-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"java-1_5_0-ibm-alsa-1.5.0_sr16.6-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"java-1_5_0-ibm-jdbc-1.5.0_sr16.6-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"java-1_5_0-ibm-plugin-1.5.0_sr16.6-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"java-1_5_0-ibm-32bit-1.5.0_sr16.6-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"java-1_5_0-ibm-devel-32bit-1.5.0_sr16.6-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"java-1_5_0-ibm-1.5.0_sr16.6-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"java-1_5_0-ibm-devel-1.5.0_sr16.6-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"java-1_5_0-ibm-fonts-1.5.0_sr16.6-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"i586", reference:"java-1_5_0-ibm-alsa-1.5.0_sr16.6-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"i586", reference:"java-1_5_0-ibm-jdbc-1.5.0_sr16.6-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"i586", reference:"java-1_5_0-ibm-plugin-1.5.0_sr16.6-0.5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "IBM Java 5");
}
