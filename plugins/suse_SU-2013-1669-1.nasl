#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2013:1669-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83601);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2015/07/23 15:18:07 $");

  script_cve_id("CVE-2013-3829", "CVE-2013-4002", "CVE-2013-4041", "CVE-2013-5372", "CVE-2013-5375", "CVE-2013-5774", "CVE-2013-5778", "CVE-2013-5780", "CVE-2013-5782", "CVE-2013-5783", "CVE-2013-5790", "CVE-2013-5797", "CVE-2013-5801", "CVE-2013-5802", "CVE-2013-5809", "CVE-2013-5814", "CVE-2013-5829", "CVE-2013-5840", "CVE-2013-5842", "CVE-2013-5843");
  script_bugtraq_id(61310, 63082, 63095, 63101, 63102, 63103, 63106, 63115, 63118, 63120, 63121, 63128, 63134, 63135, 63137, 63143, 63146, 63147, 63148, 63149, 63150, 63151, 63154, 63224, 63619, 63621);
  script_osvdb_id(95418, 98524, 98525, 98526, 98531, 98532, 98533, 98544, 98546, 98548, 98549, 98550, 98552, 98553, 98559, 98560, 98562, 98564, 98565, 98567, 98569, 98571, 98572, 98716, 99532, 99533);

  script_name(english:"SUSE SLES10 Security Update : IBM Java 5 (SUSE-SU-2013:1669-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IBM Java 5 SR16-FP4 has been released which fixes lots of bugs and
security issues.

More information can be found on :

http://www.ibm.com/developerworks/java/jdk/alerts/

CVEs fixed: CVE-2013-4041, CVE-2013-5375, CVE-2013-5372,
CVE-2013-5843, CVE-2013-5830, CVE-2013-5829, CVE-2013-5842,
CVE-2013-5782, CVE-2013-5817, CVE-2013-5809, CVE-2013-5814,
CVE-2013-5802, CVE-2013-5804, CVE-2013-5783, CVE-2013-3829,
CVE-2013-4002, CVE-2013-5774, CVE-2013-5825, CVE-2013-5840,
CVE-2013-5801, CVE-2013-5778, CVE-2013-5849, CVE-2013-5790,
CVE-2013-5780, CVE-2013-5797, CVE-2013-5803

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=5081cdae28bd8b3832e528c33135eb2a
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9a37c029"
  );
  # http://download.suse.com/patch/finder/?keywords=72ed1fe5b55bbe85bd66cb799815e617
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?def7aaa9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ibm.com/developerworks/java/jdk/alerts/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/849212"
  );
  # https://www.suse.com/support/update/announcement/2013/suse-su-20131669-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f708c4a8"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/14");
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
if (os_ver == "SLES10" && (! ereg(pattern:"^4|3$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-32bit-1.5.0_sr16.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-devel-32bit-1.5.0_sr16.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-alsa-32bit-1.5.0_sr16.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-alsa-1.5.0_sr16.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-jdbc-1.5.0_sr16.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-plugin-1.5.0_sr16.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"java-1_5_0-ibm-32bit-1.5.0_sr16.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"java-1_5_0-ibm-devel-32bit-1.5.0_sr16.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"java-1_5_0-ibm-1.5.0_sr16.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"java-1_5_0-ibm-devel-1.5.0_sr16.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"java-1_5_0-ibm-fonts-1.5.0_sr16.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"java-1_5_0-ibm-alsa-1.5.0_sr16.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"java-1_5_0-ibm-jdbc-1.5.0_sr16.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"java-1_5_0-ibm-plugin-1.5.0_sr16.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"java-1_5_0-ibm-32bit-1.5.0_sr16.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"java-1_5_0-ibm-devel-32bit-1.5.0_sr16.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"java-1_5_0-ibm-alsa-32bit-1.5.0_sr16.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"java-1_5_0-ibm-alsa-1.5.0_sr16.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"java-1_5_0-ibm-jdbc-1.5.0_sr16.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"java-1_5_0-ibm-plugin-1.5.0_sr16.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"java-1_5_0-ibm-32bit-1.5.0_sr16.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"java-1_5_0-ibm-devel-32bit-1.5.0_sr16.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"java-1_5_0-ibm-1.5.0_sr16.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"java-1_5_0-ibm-devel-1.5.0_sr16.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"java-1_5_0-ibm-fonts-1.5.0_sr16.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"i586", reference:"java-1_5_0-ibm-alsa-1.5.0_sr16.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"i586", reference:"java-1_5_0-ibm-jdbc-1.5.0_sr16.4-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"i586", reference:"java-1_5_0-ibm-plugin-1.5.0_sr16.4-0.5.1")) flag++;


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
