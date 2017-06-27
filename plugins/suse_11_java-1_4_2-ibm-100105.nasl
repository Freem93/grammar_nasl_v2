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
  script_id(43857);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/21 20:21:20 $");

  script_cve_id("CVE-2009-3867", "CVE-2009-3869", "CVE-2009-3871", "CVE-2009-3874", "CVE-2009-3875");

  script_name(english:"SuSE 11 Security Update : IBM Java 1.4.2 (SAT Patch Number 1744)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IBM Java 1.4.2 was updated to 13 fp3.

The following security issues were fixed :

  - A buffer overflow vulnerability in the Java Runtime
    Environment audio system might allow an untrusted applet
    or Java Web Start application to escalate privileges.
    For example, an untrusted applet might grant itself
    permissions to read and write local files, or run local
    applications that are accessible to the user running the
    untrusted applet. (CVE-2009-3867)

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
    the user running the untrusted applet. (CVE-2009-3874)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=561831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3867.html"
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
    value:"http://support.novell.com/security/cve/CVE-2009-3874.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3875.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 1744.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java JRE AWT setDiffICM Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119, 189, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_4_2-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_4_2-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_4_2-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/12");
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
if (rpm_check(release:"SLES11", sp:0, reference:"java-1_4_2-ibm-1.4.2_sr13.3-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"java-1_4_2-ibm-jdbc-1.4.2_sr13.3-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"java-1_4_2-ibm-plugin-1.4.2_sr13.3-1.1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
