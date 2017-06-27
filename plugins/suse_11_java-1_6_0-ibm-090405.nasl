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
  script_id(41405);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/21 20:21:20 $");

  script_cve_id("CVE-2008-5340", "CVE-2008-5341", "CVE-2008-5342", "CVE-2008-5351", "CVE-2008-5356", "CVE-2008-5357", "CVE-2008-5358");

  script_name(english:"SuSE 11 Security Update : IBM Java 1.6.0 (SAT Patch Number 736)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings the IBM Java 6 JDK and JRE to Service Release 4. It
fixes lots of bugs and various security issues :

  - A vulnerability in the Java Runtime Environment may
    allow an untrusted Java Web Start application to
    determine the location of the Java Web Start cache and
    the username of the user running the Java Web Start
    application. (CVE-2008-5341)

  - A vulnerability in the Java Runtime Environment with
    launching Java Web Start applications may allow an
    untrusted Java Web Start application to escalate
    privileges. For example, an untrusted application may
    grant itself permissions to read and write local files
    or execute local applications that are accessible to the
    user running the untrusted application. (CVE-2008-5340)

  - The UTF-8 (Unicode Transformation Format-8) decoder in
    the Java Runtime Environment (JRE) accepts encodings
    that are longer than the 'shortest' form. This behavior
    is not a vulnerability in Java SE. However, it may be
    leveraged to exploit systems running software that
    relies on the JRE UTF-8 decoder to reject non-shortest
    form sequences. For example, non-shortest form sequences
    may be decoded into illegal URIs, which may then allow
    files that are not otherwise accessible to be read, if
    the URIs are not checked following UTF-8 decoding.
    (CVE-2008-5351)

  - A buffer vulnerability in the Java Runtime Environment
    (JRE) with processing fonts may allow an untrusted
    applet or Java Web Start application to escalate
    privileges. For example, an untrusted applet may grant
    itself permissions to read and write local files or
    execute local applications that are accessible to the
    user running the untrusted applet. (CVE-2008-5356)

  - A buffer vulnerability in the Java Runtime Environment
    (JRE) with processing fonts may allow an untrusted
    applet or Java Web Start application to escalate
    privileges. For example, an untrusted applet may grant
    itself permissions to read and write local files or
    execute local applications that are accessible to the
    user running the untrusted applet. (CVE-2008-5357)

  - A buffer overflow vulnerability in the Java Runtime
    Environment with processing GIF images may allow an
    untrusted Java Web Start application to escalate
    privileges. For example, an untrusted application may
    grant itself permissions to read and write local files
    or execute local applications that are accessible to the
    user running the untrusted applet. (CVE-2008-5358)

  - A security vulnerability in the the Java Web Start
    BasicService allows untrusted applications that are
    downloaded from another system to request local files to
    be displayed by the browser of the user running the
    untrusted application. (CVE-2008-5342)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=489052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5340.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5341.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5342.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5351.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5356.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5357.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5358.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 736.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES11", sp:0, reference:"java-1_6_0-ibm-1.6.0-124.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"java-1_6_0-ibm-fonts-1.6.0-124.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"java-1_6_0-ibm-jdbc-1.6.0-124.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"java-1_6_0-ibm-alsa-1.6.0-124.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"java-1_6_0-ibm-plugin-1.6.0-124.6.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
