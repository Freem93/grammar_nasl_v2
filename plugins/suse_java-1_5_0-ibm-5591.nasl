#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(34200);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2008-3104", "CVE-2008-3106", "CVE-2008-3108", "CVE-2008-3111", "CVE-2008-3112", "CVE-2008-3113", "CVE-2008-3114");

  script_name(english:"SuSE 10 Security Update : IBM Java 1.5 (ZYPP Patch Number 5591)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IBM Java 5 was updated to SR8 to fix various security issues :

  - Multiple vulnerabilities with unsigned applets were
    reported. A remote attacker could misuse an unsigned
    applet to connect to localhost services running on the
    host running the applet. (CVE-2008-3104)

  - A vulnerability in the XML processing API was found. A
    remote attacker who caused malicious XML to be processed
    by an untrusted applet or application was able to
    elevate permissions to access URLs on a remote host.
    (CVE-2008-3106)

  - A buffer overflow vulnerability was found in the font
    processing code. This allowed remote attackers to extend
    the permissions of an untrusted applet or application,
    allowing it to read and/or write local files, as well as
    to execute local applications accessible to the user
    running the untrusted application. (CVE-2008-3108)

  - Several buffer overflow vulnerabilities in Java Web
    Start were reported. These vulnerabilities allowed an
    untrusted Java Web Start application to elevate its
    privileges, allowing it to read and/or write local
    files, as well as to execute local applications
    accessible to the user running the untrusted
    application. (CVE-2008-3111)

  - Two file processing vulnerabilities in Java Web Start
    were found. A remote attacker, by means of an untrusted
    Java Web Start application, was able to create or delete
    arbitrary files with the permissions of the user running
    the untrusted application. (CVE-2008-3112 /
    CVE-2008-3113)

  - A vulnerability in Java Web Start when processing
    untrusted applications was reported. An attacker was
    able to acquire sensitive information, such as the cache
    location. (CVE-2008-3114)

This release also reinstates previous Crypto Export policy jars lost
between SR3 and SR8."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-3104.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-3106.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-3108.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-3111.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-3112.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-3113.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-3114.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 5591.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20, 119, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_5_0-ibm-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_5_0-ibm-demo-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_5_0-ibm-devel-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_5_0-ibm-src-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"java-1_5_0-ibm-alsa-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"java-1_5_0-ibm-jdbc-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"java-1_5_0-ibm-plugin-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"java-1_5_0-ibm-32bit-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"java-1_5_0-ibm-alsa-32bit-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"java-1_5_0-ibm-devel-32bit-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"java-1_5_0-ibm-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"java-1_5_0-ibm-demo-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"java-1_5_0-ibm-devel-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"java-1_5_0-ibm-src-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"java-1_5_0-ibm-alsa-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"java-1_5_0-ibm-jdbc-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"java-1_5_0-ibm-plugin-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"java-1_5_0-ibm-32bit-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"java-1_5_0-ibm-alsa-32bit-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"java-1_5_0-ibm-devel-32bit-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_5_0-ibm-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_5_0-ibm-devel-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_5_0-ibm-fonts-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"java-1_5_0-ibm-alsa-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"java-1_5_0-ibm-jdbc-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"java-1_5_0-ibm-plugin-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"java-1_5_0-ibm-32bit-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"java-1_5_0-ibm-alsa-32bit-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"java-1_5_0-ibm-devel-32bit-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"java-1_5_0-ibm-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"java-1_5_0-ibm-devel-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"java-1_5_0-ibm-fonts-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"java-1_5_0-ibm-alsa-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"java-1_5_0-ibm-jdbc-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"java-1_5_0-ibm-plugin-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"java-1_5_0-ibm-32bit-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"java-1_5_0-ibm-alsa-32bit-1.5.0_sr8-1.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"java-1_5_0-ibm-devel-32bit-1.5.0_sr8-1.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
