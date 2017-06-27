#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2012:1489-2.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83567);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/05/19 18:02:19 $");

  script_cve_id("CVE-2012-1531", "CVE-2012-1532", "CVE-2012-1533", "CVE-2012-3159", "CVE-2012-3216", "CVE-2012-5067", "CVE-2012-5070", "CVE-2012-5071", "CVE-2012-5073", "CVE-2012-5075", "CVE-2012-5076", "CVE-2012-5077", "CVE-2012-5079", "CVE-2012-5081", "CVE-2012-5083", "CVE-2012-5084", "CVE-2012-5087", "CVE-2012-5088", "CVE-2012-5089");
  script_bugtraq_id(56025, 56033, 56039, 56043, 56046, 56051, 56054, 56055, 56056, 56057, 56058, 56059, 56061, 56063, 56065, 56070, 56071, 56072, 56075, 56079, 56080, 56081, 56082, 56083);

  script_name(english:"SUSE SLES11 Security Update : IBM Java 1.7.0 (SUSE-SU-2012:1489-2)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IBM Java 1.7.0 has been updated to SR3 which fixes bugs and security
issues.

More information can be found on :

http://www.ibm.com/developerworks/java/jdk/alerts/

CVEs fixed: CVE-2012-3159, CVE-2012-3216, CVE-2012-5070,
CVE-2012-5067, CVE-2012-3143, CVE-2012-5076, CVE-2012-5077,
CVE-2012-5073, CVE-2012-5074, CVE-2012-5075, CVE-2012-5083,
CVE-2012-5083, CVE-2012-5072, CVE-2012-1531, CVE-2012-5081,
CVE-2012-1532, CVE-2012-1533, CVE-2012-5069, CVE-2012-5071,
CVE-2012-5084, CVE-2012-5087, CVE-2012-5086, CVE-2012-5079,
CVE-2012-5088, CVE-2012-5089

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=6af80338101f9a022afdf21e00326b65
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e90a121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ibm.com/developerworks/java/jdk/alerts/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/788750"
  );
  # https://www.suse.com/support/update/announcement/2012/suse-su-20121489-2.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d3a7b9d6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11 SP2 :

zypper in -t patch sdksp2-java-1_7_0-ibm-7046

SUSE Linux Enterprise Server 11 SP2 for VMware :

zypper in -t patch slessp2-java-1_7_0-ibm-7046

SUSE Linux Enterprise Server 11 SP2 :

zypper in -t patch slessp2-java-1_7_0-ibm-7046

SUSE Linux Enterprise Java 11 SP2 :

zypper in -t patch slejsp2-java-1_7_0-ibm-7046

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Method Handle Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/21");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^2$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"java-1_7_0-ibm-plugin-1.7.0_sr3.0-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"java-1_7_0-ibm-alsa-1.7.0_sr3.0-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"java-1_7_0-ibm-1.7.0_sr3.0-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"java-1_7_0-ibm-jdbc-1.7.0_sr3.0-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"java-1_7_0-ibm-plugin-1.7.0_sr3.0-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"java-1_7_0-ibm-alsa-1.7.0_sr3.0-0.5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "IBM Java 1.7.0");
}
