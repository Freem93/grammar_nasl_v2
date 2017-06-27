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
  script_id(43872);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/21 20:21:20 $");

  script_cve_id("CVE-2009-0217", "CVE-2009-3865", "CVE-2009-3866", "CVE-2009-3867", "CVE-2009-3868", "CVE-2009-3869", "CVE-2009-3871", "CVE-2009-3872", "CVE-2009-3873", "CVE-2009-3874", "CVE-2009-3875", "CVE-2009-3876", "CVE-2009-3877");

  script_name(english:"SuSE 11 Security Update : IBM Java 1.6.0 (SAT Patch Number 1748)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IBM Java 6 was updated to Service Refresh 7.

The following security issues were fixed :

  - A vulnerability in the Java Runtime Environment with
    decoding DER encoded data might allow a remote client to
    cause the JRE to crash, resulting in a denial of service
    condition. (CVE-2009-3876 / CVE-2009-3877)

  - A buffer overflow vulnerability in the Java Runtime
    Environment audio system might allow an untrusted applet
    or Java Web Start application to escalate privileges.
    For example, an untrusted applet might grant itself
    permissions to read and write local files, or run local
    applications that are accessible to the user running the
    untrusted applet. (CVE-2009-3867)

  - A buffer overflow vulnerability in the Java Runtime
    Environment with parsing image files might allow an
    untrusted applet or Java Web Start application to
    escalate privileges. For example, an untrusted applet
    might grant itself permissions to read and write local
    files, or run local applications that are accessible to
    the user running the untrusted applet. (CVE-2009-3868)

  - An integer overflow vulnerability in the Java Runtime
    Environment with reading JPEG files might allow an
    untrusted applet or Java Web Start application to
    escalate privileges. For example, an untrusted applet
    might grant itself permissions to read and write local
    files, or run local applications that are accessible to
    the user running the untrusted applet. (CVE-2009-3872)

  - A buffer overflow vulnerability in the Java Runtime
    Environment with processing JPEG files might allow an
    untrusted applet or Java Web Start application to
    escalate privileges. For example, an untrusted applet
    might grant itself permissions to read and write local
    files, or run local applications that are accessible to
    the user running the untrusted applet. (CVE-2009-3873)

  - A security vulnerability in the Java Runtime Environment
    with verifying HMAC digests might allow authentication
    to be bypassed. This action can allow a user to forge a
    digital signature that would be accepted as valid.
    Applications that validate HMAC-based digital signatures
    might be vulnerable to this type of attack.
    (CVE-2009-3875)

  - A command execution vulnerability in the Java Runtime
    Environment Deployment Toolkit might be used to run
    arbitrary code. This issue might occur as the result of
    a user of the Java Runtime Environment viewing a
    specially crafted web page that exploits this
    vulnerability. (CVE-2009-3865)

  - A buffer overflow vulnerability in the Java Runtime
    Environment with processing image files might allow an
    untrusted applet or Java Web Start application to
    escalate privileges. For example, an untrusted applet
    might grant itself permissions to read and write local
    files or run local applications that are accessible to
    the user running the untrusted applet. (CVE-2009-3869)

  - A buffer overflow vulnerability in the Java Runtime
    Environment with processing image files might allow an
    untrusted applet or Java Web Start application to
    escalate privileges. For example, an untrusted applet
    might grant itself permissions to read and write local
    files or run local applications that are accessible to
    the user running the untrusted applet. (CVE-2009-3871)

  - A security vulnerability in the Java Web Start Installer
    might be used to allow an untrusted Java Web Start
    application to run as a trusted application and run
    arbitrary code. This issue might occur as the result of
    a user of the Java Runtime Environment viewing a
    specially crafted web page that exploits this
    vulnerability. (CVE-2009-3866)

  - An integer overflow vulnerability in the Java Runtime
    Environment with processing JPEG images might allow an
    untrusted applet or Java Web Start application to
    escalate privileges. For example, an untrusted applet
    might grant itself permissions to read and write local
    files or run local applications that are accessible to
    the user running the untrusted applet. (CVE-2009-3874)

  - A vulnerability with verifying HMAC-based XML digital
    signatures in the XML Digital Signature implementation
    included with the Java Runtime Environment (JRE) might
    allow authentication to be bypassed. Applications that
    validate HMAC-based XML digital signatures might be
    vulnerable to this type of attack. (CVE-2009-0217)

Note: This vulnerability cannot be exploited by an untrusted applet or
Java Web Start application."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=561859"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0217.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3865.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3866.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3867.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3868.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3869.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3871.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3872.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3873.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3874.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3875.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3876.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3877.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 1748.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java JRE AWT setDiffICM Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94, 119, 189, 264, 310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (pl) audit(AUDIT_OS_NOT, "SuSE 11.0");


flag = 0;
if (rpm_check(release:"SLES11", sp:0, reference:"java-1_6_0-ibm-1.6.0_sr7.0-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"java-1_6_0-ibm-fonts-1.6.0_sr7.0-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"java-1_6_0-ibm-jdbc-1.6.0_sr7.0-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"java-1_6_0-ibm-alsa-1.6.0_sr7.0-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"java-1_6_0-ibm-plugin-1.6.0_sr7.0-1.1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
