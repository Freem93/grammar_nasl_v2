#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1085-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(84285);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/05/11 13:40:22 $");

  script_cve_id("CVE-2015-0138", "CVE-2015-0192", "CVE-2015-0204", "CVE-2015-0459", "CVE-2015-0469", "CVE-2015-0477", "CVE-2015-0478", "CVE-2015-0480", "CVE-2015-0488", "CVE-2015-0491", "CVE-2015-1914", "CVE-2015-2808");
  script_bugtraq_id(71936, 73326, 73684, 74072, 74083, 74094, 74104, 74111, 74119, 74147, 74545, 74645);
  script_osvdb_id(15435, 116794, 117855, 119390, 120702, 120709, 120710, 120712, 120713, 120714, 121762, 121763);

  script_name(english:"SUSE SLES10 Security Update : IBM Java (SUSE-SU-2015:1085-1) (Bar Mitzvah) (FREAK)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IBM Java 1.5.0 was updated to SR16-FP10 fixing security issues and
bugs.

Tabulated information can be found on: <a
href='http://www.ibm.com/developerworks/java/jdk/alerts/#IBM_Security_
Update_May_2015'>http://www.ibm.com/developerworks/java/jdk/alerts/#IB
M_Security_Update_May_2015</a>

CVE-2015-0192 CVE-2015-2808 CVE-2015-1914 CVE-2015-0138 CVE-2015-0491
CVE-2015-0459 CVE-2015-0469 CVE-2015-0480 CVE-2015-0488 CVE-2015-0478
CVE-2015-0477 CVE-2015-0204

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://www.ibm.com/developerworks/java/jdk/alerts/#IBM_Security_Update_May_2015'
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa9a758f"
  );
  # http://www.ibm.com/developerworks/java/jdk/alerts/#IBM_Security_Update_May_2015</a
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?181e85c0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931702"
  );
  # https://download.suse.com/patch/finder/?keywords=75c7c1e62322e337b7527c52591a9e20
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?48ae2022"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151085-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f3ed40"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected IBM Java packages"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UR");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/18");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/19");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/11");
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
if (! ereg(pattern:"^(SLES10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES10" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-32bit-1.5.0_sr16.10-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-devel-32bit-1.5.0_sr16.10-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-alsa-32bit-1.5.0_sr16.10-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-alsa-1.5.0_sr16.10-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-jdbc-1.5.0_sr16.10-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-plugin-1.5.0_sr16.10-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"java-1_5_0-ibm-32bit-1.5.0_sr16.10-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"java-1_5_0-ibm-devel-32bit-1.5.0_sr16.10-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"java-1_5_0-ibm-1.5.0_sr16.10-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"java-1_5_0-ibm-devel-1.5.0_sr16.10-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"java-1_5_0-ibm-fonts-1.5.0_sr16.10-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"java-1_5_0-ibm-alsa-1.5.0_sr16.10-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"java-1_5_0-ibm-jdbc-1.5.0_sr16.10-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"java-1_5_0-ibm-plugin-1.5.0_sr16.10-0.6.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "IBM Java");
}
