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
  script_id(56004);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/03/04 16:00:57 $");

  script_cve_id("CVE-2011-0786", "CVE-2011-0802", "CVE-2011-0814", "CVE-2011-0815", "CVE-2011-0862", "CVE-2011-0865", "CVE-2011-0866", "CVE-2011-0867", "CVE-2011-0871", "CVE-2011-0872");

  script_name(english:"SuSE 11.1 Security Update : IBM Java (SAT Patch Number 5014)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IBM Java 1.4.2 SR 13 Fixpack 10 has been released and fixes various
bugs and security issues.

The following security issues have been fixed :

  - Unspecified vulnerability in the Java Runtime
    Environment (JRE) component in Oracle Java SE 6 Update
    25 and earlier, 5.0 Update 29 and earlier, and 1.4.2_31
    and earlier allows remote untrusted Java Web Start
    applications and untrusted Java applets to affect
    integrity via unknown vectors related to
    Deserialization. (CVE-2011-0865)

  - Unspecified vulnerability in the Java Runtime
    Environment (JRE) component in Oracle Java SE 6 Update
    25 and earlier, 5.0 Update 29 and earlier, and 1.4.2_31
    and earlier, when running on Windows, allows remote
    untrusted Java Web Start applications and untrusted Java
    applets to affect confidentiality, integrity, and
    availability via unknown vectors related to Java Runtime
    Environment. (CVE-2011-0866)

  - Unspecified vulnerability in the Java Runtime
    Environment (JRE) component in Oracle Java SE 6 Update
    25 and earlier, when running on Windows, allows remote
    untrusted Java Web Start applications and untrusted Java
    applets to affect confidentiality, integrity, and
    availability via unknown vectors related to Deployment,
    a different vulnerability than CVE-2011-0786.
    (CVE-2011-0802)

  - Unspecified vulnerability in the Java Runtime
    Environment (JRE) component in Oracle Java SE 6 Update
    25 and earlier, 5.0 Update 29 and earlier, and 1.4.2_31
    and earlier allows remote attackers to affect
    confidentiality, integrity, and availability via unknown
    vectors related to Sound, a different vulnerability than
    CVE-2011-0802. (CVE-2011-0814)

  - Unspecified vulnerability in the Java Runtime
    Environment (JRE) component in Oracle Java SE 6 Update
    25 and earlier, 5.0 Update 29 and earlier, and 1.4.2_31
    and earlier allows remote untrusted Java Web Start
    applications and untrusted Java applets to affect
    confidentiality, integrity, and availability via unknown
    vectors related to AWT. (CVE-2011-0815)

  - Multiple unspecified vulnerabilities in the Java Runtime
    Environment (JRE) component in Oracle Java SE 6 Update
    25 and earlier, 5.0 Update 29 and earlier, and 1.4.2_31
    and earlier allow remote attackers to affect
    confidentiality, integrity, and availability via unknown
    vectors related to 2D. (CVE-2011-0862)

  - Unspecified vulnerability in the Java Runtime
    Environment (JRE) component in Oracle Java SE 6 Update
    25 and earlier, 5.0 Update 29 and earlier, and 1.4.2_31
    and earlier allows remote untrusted Java Web Start
    applications and untrusted Java applets to affect
    confidentiality via unknown vectors related to
    Networking. (CVE-2011-0867)

  - Unspecified vulnerability in the Java Runtime
    Environment (JRE) component in Oracle Java SE 6 Update
    25 and earlier, 5.0 Update 29 and earlier, and 1.4.2_31
    and earlier allows remote untrusted Java Web Start
    applications and untrusted Java applets to affect
    confidentiality, integrity, and availability via unknown
    vectors related to Swing. (CVE-2011-0871)

  - Unspecified vulnerability in the Java Runtime
    Environment (JRE) component in Oracle Java SE 6 Update
    25 and earlier allows remote attackers to affect
    availability via unknown vectors related to NIO.
    (CVE-2011-0872)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=711195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0786.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0802.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0814.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0815.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0862.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0865.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0866.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0867.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0871.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0872.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 5014.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_4_2-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_4_2-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_4_2-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLES11", sp:1, reference:"java-1_4_2-ibm-1.4.2_sr13.10-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"java-1_4_2-ibm-jdbc-1.4.2_sr13.10-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"java-1_4_2-ibm-plugin-1.4.2_sr13.10-0.4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
