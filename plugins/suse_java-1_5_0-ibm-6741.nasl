#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(49863);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2009-2493", "CVE-2009-3867", "CVE-2009-3868", "CVE-2009-3869", "CVE-2009-3871", "CVE-2009-3872", "CVE-2009-3873", "CVE-2009-3874", "CVE-2009-3875", "CVE-2009-3876", "CVE-2009-3877");

  script_name(english:"SuSE 10 Security Update : IBM Java 1.5.0 (ZYPP Patch Number 6741)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IBM Java 5 was updated to Service Refresh 11. It fixes lots of bugs
and security issues.

The timezone update to 1.6.9s (with the latest Fiji change).

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

  - An integer overflow vulnerability in the Java Runtime
    Environment with processing JPEG images might allow an
    untrusted applet or Java Web Start application to
    escalate privileges. For example, an untrusted applet
    might grant itself permissions to read and write local
    files or run local applications that are accessible to
    the user running the untrusted applet. (CVE-2009-3874)

  - The Java Runtime Environment includes the Java Web Start
    technology that uses the Java Web Start ActiveX control
    to launch Java Web Start in Internet Explorer. A
    security vulnerability in the Active Template Library
    (ATL) in various releases of Microsoft Visual Studio,
    which is used by the Java Web Start ActiveX control,
    might allow the Java Web Start ActiveX control to be
    leveraged to run arbitrary code. This might occur as the
    result of a user of the Java Runtime Environment viewing
    a specially crafted web page that exploits this
    vulnerability. (CVE-2009-2493)

Please also see http://www.ibm.com/developerworks/java/jdk/alerts/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2493.html"
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
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6741.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java JRE AWT setDiffICM Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119, 189, 264, 310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:3, reference:"java-1_5_0-ibm-1.5.0_sr11-0.4.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"java-1_5_0-ibm-demo-1.5.0_sr11-0.4.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"java-1_5_0-ibm-devel-1.5.0_sr11-0.4.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"java-1_5_0-ibm-fonts-1.5.0_sr11-0.4.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"java-1_5_0-ibm-src-1.5.0_sr11-0.4.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"java-1_5_0-ibm-jdbc-1.5.0_sr11-0.4.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"java-1_5_0-ibm-plugin-1.5.0_sr11-0.4.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"java-1_5_0-ibm-32bit-1.5.0_sr11-0.4.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"java-1_5_0-ibm-alsa-32bit-1.5.0_sr11-0.4.2")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"java-1_5_0-ibm-devel-32bit-1.5.0_sr11-0.4.2")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"java-1_5_0-ibm-1.5.0_sr11-0.4.2")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"java-1_5_0-ibm-devel-1.5.0_sr11-0.4.2")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"java-1_5_0-ibm-fonts-1.5.0_sr11-0.4.2")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"java-1_5_0-ibm-jdbc-1.5.0_sr11-0.4.2")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"java-1_5_0-ibm-plugin-1.5.0_sr11-0.4.2")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"java-1_5_0-ibm-32bit-1.5.0_sr11-0.4.2")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"java-1_5_0-ibm-alsa-32bit-1.5.0_sr11-0.4.2")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"java-1_5_0-ibm-devel-32bit-1.5.0_sr11-0.4.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
