#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2012:1489-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83566);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/05/19 18:02:19 $");

  script_cve_id("CVE-2012-1531", "CVE-2012-3143", "CVE-2012-3216", "CVE-2012-5071", "CVE-2012-5073", "CVE-2012-5075", "CVE-2012-5079", "CVE-2012-5081", "CVE-2012-5083", "CVE-2012-5084");
  script_bugtraq_id(56025, 56033, 56055, 56059, 56061, 56063, 56065, 56071, 56075, 56080, 56081, 56082);

  script_name(english:"SUSE SLED10 / SLES10 Security Update : IBM Java 1.5.0 (SUSE-SU-2012:1489-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IBM Java 1.5.0 has been updated to SR15 which fixes bugs and security
issues.

More information can be found on :

http://www.ibm.com/developerworks/java/jdk/alerts/

CVEs fixed: CVE-2012-3216, CVE-2012-3143, CVE-2012-5073,
CVE-2012-5075, CVE-2012-5083, CVE-2012-5083, CVE-2012-1531,
CVE-2012-5081, CVE-2012-5069, CVE-2012-5071, CVE-2012-5084,
CVE-2012-5079, CVE-2012-5089

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=bb56b08850390b907db4d458f187e204
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?be03c147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ibm.com/developerworks/java/jdk/alerts/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/788750"
  );
  # https://www.suse.com/support/update/announcement/2012/suse-su-20121489-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?212bcc4f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected IBM Java 1.5.0 packages"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_5_0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_5_0-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_5_0-ibm-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_5_0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_5_0-ibm-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_5_0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_5_0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_5_0-ibm-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/16");
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
if (! ereg(pattern:"^(SLED10|SLES10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED10 / SLES10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED10" && (! ereg(pattern:"^4$", string:sp))) audit(AUDIT_OS_NOT, "SLED10 SP4", os_ver + " SP" + sp);
if (os_ver == "SLES10" && (! ereg(pattern:"^4$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-demo-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-devel-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-fonts-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-src-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-32bit-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-alsa-32bit-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-devel-32bit-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-alsa-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-jdbc-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-plugin-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"java-1_5_0-ibm-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"java-1_5_0-ibm-demo-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"java-1_5_0-ibm-devel-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"java-1_5_0-ibm-fonts-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"java-1_5_0-ibm-src-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"java-1_5_0-ibm-alsa-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"java-1_5_0-ibm-jdbc-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"java-1_5_0-ibm-plugin-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-32bit-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-devel-32bit-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-jdbc-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-plugin-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-alsa-32bit-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"java-1_5_0-ibm-alsa-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"java-1_5_0-ibm-32bit-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"java-1_5_0-ibm-devel-32bit-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"java-1_5_0-ibm-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"java-1_5_0-ibm-devel-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"java-1_5_0-ibm-fonts-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"java-1_5_0-ibm-jdbc-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"java-1_5_0-ibm-plugin-1.5.0_sr15.0-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"i586", reference:"java-1_5_0-ibm-alsa-1.5.0_sr15.0-0.5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "IBM Java 1.5.0");
}
