#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(34036);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2008-3104", "CVE-2008-3107", "CVE-2008-3108", "CVE-2008-3111", "CVE-2008-3112", "CVE-2008-3113", "CVE-2008-3114");

  script_name(english:"SuSE 10 Security Update : Java 1.4.2 (ZYPP Patch Number 5431)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun Java was updated to 1.4.2u18 to fix following security
vulnerabilities :

  - Unspecified vulnerability in Sun Java Web Start in JDK
    and JRE 6 before Update 7, JDK and JRE 5.0 before Update
    16, and SDK and JRE 1.4.x before 1.4.2_18 allows
    context-dependent attackers to obtain sensitive
    information (the cache location) via an untrusted
    application, aka CR 6704074. (CVE-2008-3114)

  - Unspecified vulnerability in Sun Java Web Start in JDK
    and JRE 5.0 before Update 16 and SDK and JRE 1.4.x
    before 1.4.2_18 allows remote attackers to create or
    delete arbitrary files via an untrusted application, aka
    CR 6704077. (CVE-2008-3113)

  - Unspecified vulnerability in Sun Java Web Start in JDK
    and JRE 6 before Update 7, JDK and JRE 5.0 before Update
    16, and SDK and JRE 1.4.x before 1.4.2_18 allows remote
    attackers to create arbitrary files via an untrusted
    application, aka CR 6703909. (CVE-2008-3112)

  - Multiple buffer overflows in Sun Java Web Start in JDK
    and JRE 6 before Update 4, JDK and JRE 5.0 before Update
    16, and SDK and JRE 1.4.x before 1.4.2_18 allow
    context-dependent attackers to gain privileges via an
    untrusted application, as demonstrated by an application
    that grants itself privileges to (1) read local files,
    (2) write to local files, or (3) execute local programs,
    aka CR 6557220. (CVE-2008-3111)

  - Buffer overflow in Sun Java Runtime Environment (JRE) in
    JDK and JRE 5.0 before Update 10, SDK and JRE 1.4.x
    before 1.4.2_18, and SDK and JRE 1.3.x before 1.3.1_23
    allows context-dependent attackers to gain privileges
    via unspecified vectors related to font processing.
    (CVE-2008-3108)

  - Unspecified vulnerability in the Virtual Machine in Sun
    Java Runtime Environment (JRE) in JDK and JRE 6 before
    Update 7, JDK and JRE 5.0 before Update 16, and SDK and
    JRE 1.4.x before 1.4.2_18 allows context-dependent
    attackers to gain privileges via an untrusted (1)
    application or (2) applet, as demonstrated by an
    application or applet that grants itself privileges to
    (a) read local files, (b) write to local files, or (c)
    execute local programs. (CVE-2008-3107)

  - Multiple unspecified vulnerabilities in Sun Java Runtime
    Environment (JRE) in JDK and JRE 6 before Update 7, JDK
    and JRE 5.0 before Update 16, SDK and JRE 1.4.x before
    1.4.2_18, and SDK and JRE 1.3.x before 1.3.1_23 allow
    remote attackers to violate the security model for an
    applet's outbound connections by connecting to localhost
    services running on the machine that loaded the applet.
    (CVE-2008-3104)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-3104.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-3107.html"
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
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 5431.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20, 119, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/24");
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
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-1.4.2.18-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-alsa-1.4.2.18-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-demo-1.4.2.18-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-devel-1.4.2.18-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-jdbc-1.4.2.18-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-plugin-1.4.2.18-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-src-1.4.2.18-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"java-1_4_2-sun-1.4.2.18-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"java-1_4_2-sun-alsa-1.4.2.18-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"java-1_4_2-sun-demo-1.4.2.18-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"java-1_4_2-sun-devel-1.4.2.18-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"java-1_4_2-sun-jdbc-1.4.2.18-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"java-1_4_2-sun-plugin-1.4.2.18-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"java-1_4_2-sun-src-1.4.2.18-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_4_2-sun-1.4.2.18-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_4_2-sun-alsa-1.4.2.18-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_4_2-sun-devel-1.4.2.18-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_4_2-sun-jdbc-1.4.2.18-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_4_2-sun-plugin-1.4.2.18-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"java-1_4_2-sun-1.4.2.18-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"java-1_4_2-sun-alsa-1.4.2.18-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"java-1_4_2-sun-devel-1.4.2.18-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"java-1_4_2-sun-jdbc-1.4.2.18-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"java-1_4_2-sun-plugin-1.4.2.18-0.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
