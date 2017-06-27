#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(31772);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2008-1158", "CVE-2008-1185", "CVE-2008-1186", "CVE-2008-1187", "CVE-2008-1188", "CVE-2008-1189", "CVE-2008-1190", "CVE-2008-1191", "CVE-2008-1192", "CVE-2008-1195", "CVE-2008-1196");

  script_name(english:"SuSE 10 Security Update : Sun Java (ZYPP Patch Number 5131)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun Java was updated to 1.4.2u17 to fix following security
vulnerabilities :

  - Unspecified vulnerability in the Virtual Machine for Sun
    Java Runtime Environment (JRE) and JDK 6 Update 4 and
    earlier, 5.0 Update 14 and earlier, and SDK/JRE 1.4.2_16
    and earlier allows remote attackers should gain
    privileges via an untrusted application or applet, a
    different issue than CVE-2008-1186. (CVE-2008-1158)

  - Unspecified vulnerability in the Virtual Machine for Sun
    Java Runtime Environment (JRE) and JDK 5.0 Update 13 and
    earlier, and SDK/JRE 1.4.2_16 and earlier, allows remote
    attackers to gain privileges via an untrusted
    application or applet, a different issue than
    CVE-2008-1185. (CVE-2008-1186)

  - Unspecified vulnerability in Sun Java Runtime
    Environment (JRE) and JDK 6 Update 4 and earlier, 5.0
    Update 14 and earlier, and SDK/JRE 1.4.2_16 and earlier
    allows remote attackers to cause a denial of service
    (JRE crash) and possibly execute arbitrary code via
    unknown vectors related to XSLT transforms.
    (CVE-2008-1187)

  - Buffer overflow in Java Web Start in Sun JDK and JRE 6
    Update 4 and earlier, 5.0 Update 14 and earlier, and
    SDK/JRE 1.4.2_16 and earlier allows remote attackers to
    execute arbitrary code via unknown vectors, a different
    issue than CVE-2008-1188. (CVE-2008-1189)

  - Unspecified vulnerability in Java Web Start in Sun JDK
    and JRE 6 Update 4 and earlier, 5.0 Update 14 and
    earlier, and SDK/JRE 1.4.2_16 and earlier allows remote
    attackers to gain privileges via an untrusted
    application, a different issue than CVE-2008-1191.
    (CVE-2008-1190)

  - Unspecified vulnerability in the Java Plug-in for Sun
    JDK and JRE 6 Update 4 and earlier, and 5.0 Update 14
    and earlier; and SDK and JRE 1.4.2_16 and earlier, and
    1.3.1_21 and earlier; allows remote attackers to bypass
    the same origin policy and 'execute local applications'
    via unknown vectors. (CVE-2008-1192)

  - Unspecified vulnerability in Sun JDK and Java Runtime
    Environment (JRE) 6 Update 4 and earlier and 5.0 Update
    14 and earlier; and SDK and JRE 1.4.2_16 and earlier;
    allows remote attackers to access arbitrary network
    services on the local host via unspecified vectors
    related to JavaScript and Java APIs. (CVE-2008-1195)

  - Stack-based buffer overflow in Java Web Start
    (javaws.exe) in Sun JDK and JRE 6 Update 4 and earlier
    and 5.0 Update 14 and earlier; and SDK and JRE 1.4.2_16
    and earlier; allows remote attackers to execute
    arbitrary code via a crafted JNLP file. (CVE-2008-1196)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1158.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1185.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1186.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1187.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1188.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1189.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1190.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1191.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1192.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1195.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1196.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 5131.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20, 119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/04");
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
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-1.4.2.17-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-alsa-1.4.2.17-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-demo-1.4.2.17-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-devel-1.4.2.17-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-jdbc-1.4.2.17-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-plugin-1.4.2.17-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"java-1_4_2-sun-src-1.4.2.17-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_4_2-sun-1.4.2.17-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_4_2-sun-alsa-1.4.2.17-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_4_2-sun-devel-1.4.2.17-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_4_2-sun-jdbc-1.4.2.17-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"java-1_4_2-sun-plugin-1.4.2.17-0.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
