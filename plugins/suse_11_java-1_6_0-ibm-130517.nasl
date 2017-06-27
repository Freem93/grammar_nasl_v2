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
  script_id(66616);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/21 20:21:20 $");

  script_cve_id("CVE-2013-0401", "CVE-2013-1491", "CVE-2013-1537", "CVE-2013-1540", "CVE-2013-1557", "CVE-2013-1563", "CVE-2013-1569", "CVE-2013-2383", "CVE-2013-2384", "CVE-2013-2394", "CVE-2013-2417", "CVE-2013-2418", "CVE-2013-2419", "CVE-2013-2420", "CVE-2013-2422", "CVE-2013-2424", "CVE-2013-2429", "CVE-2013-2430", "CVE-2013-2432", "CVE-2013-2433", "CVE-2013-2435", "CVE-2013-2440");

  script_name(english:"SuSE 11.2 / 11.3 Security Update : IBM Java (SAT Patch Numbers 7744 / 7920)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IBM Java 1.6.0 has been updated to SR13-FP2 which fixes bugs and
security issues.

http://www.ibm.com/developerworks/java/jdk/alerts/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=592934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819288"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0401.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1491.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1537.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1540.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1557.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1563.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1569.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2383.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2384.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2394.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2417.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2418.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2419.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2420.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2422.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2424.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2429.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2430.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2432.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2433.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2435.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2440.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 7744 / 7920 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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


flag = 0;
if (rpm_check(release:"SLES11", sp:2, reference:"java-1_6_0-ibm-1.6.0_sr13.2-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"java-1_6_0-ibm-fonts-1.6.0_sr13.2-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"java-1_6_0-ibm-jdbc-1.6.0_sr13.2-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"java-1_6_0-ibm-alsa-1.6.0_sr13.2-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"java-1_6_0-ibm-plugin-1.6.0_sr13.2-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"java-1_6_0-ibm-plugin-1.6.0_sr13.2-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"java-1_6_0-ibm-1.6.0_sr13.2-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"java-1_6_0-ibm-fonts-1.6.0_sr13.2-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"java-1_6_0-ibm-jdbc-1.6.0_sr13.2-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"java-1_6_0-ibm-alsa-1.6.0_sr13.2-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"java-1_6_0-ibm-plugin-1.6.0_sr13.2-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"java-1_6_0-ibm-plugin-1.6.0_sr13.2-0.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
