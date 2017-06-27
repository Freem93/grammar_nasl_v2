#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(57210);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/03/04 16:00:57 $");

  script_cve_id("CVE-2011-0786", "CVE-2011-0788", "CVE-2011-0802", "CVE-2011-0814", "CVE-2011-0815", "CVE-2011-0817", "CVE-2011-0862", "CVE-2011-0863", "CVE-2011-0865", "CVE-2011-0866", "CVE-2011-0867", "CVE-2011-0868", "CVE-2011-0869", "CVE-2011-0871", "CVE-2011-0872", "CVE-2011-0873");

  script_name(english:"SuSE 10 Security Update : IBM Java (ZYPP Patch Number 7627)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IBM Java 1.6.0 SR9-FP2 fixes several of bugs and thew following
security issues :

  - An unspecified vulnerability in the Java Runtime
    Environment (JRE) component in Oracle Java SE 6 Update
    25 and earlier, 5.0 Update 29 and earlier, and 1.4.2_31
    and earlier allows remote untrusted Java Web Start
    applications and untrusted Java applets to affect
    integrity via unknown vectors related to
    Deserialization. (CVE-2011-0865)

  - An unspecified vulnerability in the Java Runtime
    Environment (JRE) component in Oracle Java SE 6 Update
    25 and earlier, 5.0 Update 29 and earlier, and 1.4.2_31
    and earlier, when running on Windows, allows remote
    untrusted Java Web Start applications and untrusted Java
    applets to affect confidentiality, integrity, and
    availability via unknown vectors related to Java Runtime
    Environment. (CVE-2011-0866)

  - An unspecified vulnerability in the Java Runtime
    Environment (JRE) component in Oracle Java SE 6 Update
    25 and earlier, when running on Windows, allows remote
    untrusted Java Web Start applications and untrusted Java
    applets to affect confidentiality, integrity, and
    availability via unknown vectors related to Deployment,
    a different vulnerability than CVE-2011-0788.
    (CVE-2011-0786)

  - An unspecified vulnerability in the Java Runtime
    Environment (JRE) component in Oracle Java SE 6 Update
    25 and earlier, when running on Windows, allows remote
    untrusted Java Web Start applications and untrusted Java
    applets to affect confidentiality, integrity, and
    availability via unknown vectors related to Deployment,
    a different vulnerability than CVE-2011-0786.
    (CVE-2011-0788)

  - An unspecified vulnerability in the Java Runtime
    Environment (JRE) component in Oracle Java SE 6 Update
    25 and earlier, when running on Windows, allows remote
    untrusted Java Web Start applications and untrusted Java
    applets to affect confidentiality, integrity, and
    availability via unknown vectors related to Deployment,
    a different vulnerability than CVE-2011-0786.
    (CVE-2011-0802)

  - An unspecified vulnerability in the Java Runtime
    Environment (JRE) component in Oracle Java SE 6 Update
    25 and earlier, 5.0 Update 29 and earlier, and 1.4.2_31
    and earlier allows remote attackers to affect
    confidentiality, integrity, and availability via unknown
    vectors related to Sound, a different vulnerability than
    CVE-2011-0802. (CVE-2011-0814)

  - An unspecified vulnerability in the Java Runtime
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

  - An unspecified vulnerability in the Java Runtime
    Environment (JRE) component in Oracle Java SE 6 Update
    25 and earlier, 5.0 Update 29 and earlier, and 1.4.2_31
    and earlier allows remote untrusted Java Web Start
    applications and untrusted Java applets to affect
    confidentiality via unknown vectors related to
    Networking. (CVE-2011-0867)

  - An unspecified vulnerability in the Java Runtime
    Environment (JRE) component in Oracle Java SE 6 Update
    26 and earlier allows remote untrusted Java Web Start
    applications and untrusted Java applets to affect
    confidentiality via unknown vectors related to SAAJ.
    (CVE-2011-0869)

  - An unspecified vulnerability in the Java Runtime
    Environment (JRE) component in Oracle Java SE 6 Update
    25 and earlier, when running on Windows, allows remote
    untrusted Java Web Start applications and untrusted Java
    applets to affect confidentiality, integrity, and
    availability via unknown vectors related to Deployment.
    (CVE-2011-0817)

  - An unspecified vulnerability in the Java Runtime
    Environment (JRE) component in Oracle Java SE 6 Update
    25 and earlier allows remote untrusted Java Web Start
    applications and untrusted Java applets to affect
    confidentiality, integrity, and availability via unknown
    vectors related to Deployment. (CVE-2011-0863)

  - An unspecified vulnerability in the Java Runtime
    Environment (JRE) component in Oracle Java SE 6 Update
    25 and earlier allows remote attackers to affect
    confidentiality via unknown vectors related to 2D.
    (CVE-2011-0868)

  - An unspecified vulnerability in the Java Runtime
    Environment (JRE) component in Oracle Java SE 6 Update
    25 and earlier, 5.0 Update 29 and earlier, and 1.4.2_31
    and earlier allows remote untrusted Java Web Start
    applications and untrusted Java applets to affect
    confidentiality, integrity, and availability via unknown
    vectors related to Swing. (CVE-2011-0871)

  - An unspecified vulnerability in the Java Runtime
    Environment (JRE) component in Oracle Java SE 6 Update
    25 and earlier allows remote attackers to affect
    availability via unknown vectors related to NIO.
    (CVE-2011-0872)

  - An unspecified vulnerability in the Java Runtime
    Environment (JRE) component in Oracle Java SE 6 Update
    25 and earlier, and 5.0 Update 29 and earlier, allows
    remote attackers to affect confidentiality, integrity,
    and availability via unknown vectors related to 2D.
    (CVE-2011-0873)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0786.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0788.html"
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
    value:"http://support.novell.com/security/cve/CVE-2011-0817.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0862.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0863.html"
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
    value:"http://support.novell.com/security/cve/CVE-2011-0868.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0869.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0871.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0872.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0873.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7627.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLES10", sp:4, reference:"java-1_6_0-ibm-1.6.0_sr9.2-0.9.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"java-1_6_0-ibm-devel-1.6.0_sr9.2-0.9.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"java-1_6_0-ibm-fonts-1.6.0_sr9.2-0.9.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"java-1_6_0-ibm-jdbc-1.6.0_sr9.2-0.9.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"java-1_6_0-ibm-plugin-1.6.0_sr9.2-0.9.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"java-1_6_0-ibm-alsa-1.6.0_sr9.2-0.9.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"java-1_6_0-ibm-32bit-1.6.0_sr9.2-0.9.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"java-1_6_0-ibm-alsa-32bit-1.6.0_sr9.2-0.9.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"java-1_6_0-ibm-devel-32bit-1.6.0_sr9.2-0.9.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"java-1_6_0-ibm-plugin-32bit-1.6.0_sr9.2-0.9.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
