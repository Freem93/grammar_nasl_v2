#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(66031);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/04/12 00:41:49 $");

  script_cve_id("CVE-2013-0169", "CVE-2013-0485", "CVE-2013-0809", "CVE-2013-1493");

  script_name(english:"SuSE 11.2 Security Update : java-1_7_0-ibm (SAT Patch Number 7623)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IBM Java 7 was updated to SR4-FP1, fixing bugs and security issues.

More information can be found on :

http://www.ibm.com/developerworks/java/jdk/alerts/

and on :

http://www.ibm.com/developerworks/java/jdk/aix/j764/Java7_64.fixes.htm
l#SR4FP1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813939"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0169.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0485.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0809.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1493.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 7623.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java CMM Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_7_0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_7_0-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_7_0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_7_0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLES11", sp:2, reference:"java-1_7_0-ibm-1.7.0_sr4.1-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"java-1_7_0-ibm-jdbc-1.7.0_sr4.1-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"java-1_7_0-ibm-alsa-1.7.0_sr4.1-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"java-1_7_0-ibm-plugin-1.7.0_sr4.1-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"java-1_7_0-ibm-alsa-1.7.0_sr4.1-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"java-1_7_0-ibm-plugin-1.7.0_sr4.1-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
