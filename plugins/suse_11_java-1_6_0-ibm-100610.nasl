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
  script_id(50916);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/11/18 01:35:30 $");

  script_cve_id("CVE-2010-0084", "CVE-2010-0085", "CVE-2010-0087", "CVE-2010-0088", "CVE-2010-0089", "CVE-2010-0090", "CVE-2010-0091", "CVE-2010-0092", "CVE-2010-0094", "CVE-2010-0095", "CVE-2010-0837", "CVE-2010-0838", "CVE-2010-0839", "CVE-2010-0840", "CVE-2010-0841", "CVE-2010-0842", "CVE-2010-0843", "CVE-2010-0844", "CVE-2010-0846", "CVE-2010-0847", "CVE-2010-0848", "CVE-2010-0849");

  script_name(english:"SuSE 11 Security Update : IBM Java 6 (SAT Patch Number 2548)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of IBM Java 6 to SR 8 to fixes the following security
issues :

  - Unspecified vulnerability in the Java Runtime
    Environment component in Oracle Java SE and Java for
    Business 6 Update 18, 5.0 Update 23, and 1.4.2_25 allows
    remote attackers to affect confidentiality via unknown
    vectors. (CVE-2010-0084)

  - Unspecified vulnerability in the Java Runtime
    Environment component in Oracle Java SE and Java for
    Business 6 Update 18, 5.0 Update 23, 1.4.225, and
    1.3.127 allows remote attackers to affect
    confidentiality, integrity, and availability via unknown
    vectors. (CVE-2010-0085)

  - Unspecified vulnerability in the Java Web Start, Java
    Plug-in component in Oracle Java SE and Java for
    Business 6 Update 18, 5.0 Update 23, 1.4.225, and
    1.3.127 allows remote attackers to affect
    confidentiality, integrity, and availability via unknown
    vectors. (CVE-2010-0087)

  - Unspecified vulnerability in the Java Runtime
    Environment component in Oracle Java SE and Java for
    Business 6 Update 18, 5.0 Update 23, 1.4.225, and
    1.3.127 allows remote attackers to affect
    confidentiality, integrity, and availability via unknown
    vectors. (CVE-2010-0088)

  - Unspecified vulnerability in the Java Web Start, Java
    Plug-in component in Oracle Java SE and Java for
    Business 6 Update 18, 5.0 Update 23, and 1.4.2_25 allows
    remote attackers to affect availability via unknown
    vectors. (CVE-2010-0089)

  - Unspecified vulnerability in the Java Web Start, Java
    Plug-in component in Oracle Java SE and Java for
    Business 6 Update 18 allows remote attackers to affect
    integrity and availability via unknown vectors.
    (CVE-2010-0090)

  - Unspecified vulnerability in the Java Runtime
    Environment component in Oracle Java SE and Java for
    Business 6 Update 18, 5.0 Update 23, and 1.4.2_25 allows
    remote attackers to affect confidentiality via unknown
    vectors. (CVE-2010-0091)

  - Unspecified vulnerability in the Java Runtime
    Environment component in Oracle Java SE and Java for
    Business 6 Update 18, and 5.0 Update 23 allows remote
    attackers to affect confidentiality, integrity, and
    availability via unknown vectors. (CVE-2010-0092)

  - Unspecified vulnerability in the Java Runtime
    Environment component in Oracle Java SE and Java for
    Business 6 Update 18 and 5.0 Update 23 allows remote
    attackers to affect confidentiality, integrity, and
    availability via unknown vectors. NOTE: the previous
    information was obtained from the March 2010 CPU. Oracle
    has not commented on claims from a reliable researcher
    that this is due to missing privilege checks during
    deserialization of RMIConnectionImpl objects, which
    allows remote attackers to call system-level Java
    functions via the class loader of a constructor that is
    being deserialized. (CVE-2010-0094)

  - Unspecified vulnerability in the Java Runtime
    Environment component in Oracle Java SE and Java for
    Business 6 Update 18, 5.0 Update 23, and 1.4.2_25 allows
    remote attackers to affect confidentiality, integrity,
    and availability via unknown vectors. (CVE-2010-0095)

  - Unspecified vulnerability in the Pack200 component in
    Oracle Java SE and Java for Business 6 Update 18, 5.0,
    Update, and 23 allows remote attackers to affect
    confidentiality, integrity, and availability via unknown
    vectors. (CVE-2010-0837)

  - Unspecified vulnerability in the Java 2D component in
    Oracle Java SE and Java for Business 6 Update 18, 5.0,
    Update, and 23 allows remote attackers to affect
    confidentiality, integrity, and availability via unknown
    vectors. NOTE: the previous information was obtained
    from the March 2010 CPU. Oracle has not commented on
    claims from a reliable researcher that this is a
    stack-based buffer overflow using an untrusted size
    value in the readMabCurveData function in the CMM module
    of the JVM. (CVE-2010-0838)

  - Unspecified vulnerability in the Sound component in
    Oracle Java SE and Java for Business 6 Update 18, 5.0
    Update 23, 1.4.225, and 1.3.1 27 allows remote attackers
    to affect confidentiality, integrity, and availability
    via unknown vectors. (CVE-2010-0839)

  - Unspecified vulnerability in the Java Runtime
    Environment component in Oracle Java SE and Java for
    Business 6 Update 18, 5.0 Update 23, and 1.4.2_25 allows
    remote attackers to affect confidentiality, integrity,
    and availability via unknown vectors. NOTE: the previous
    information was obtained from the March 2010 CPU. Oracle
    has not commented on claims from a reliable researcher
    that this is related to improper checks when executing
    privileged methods in the Java Runtime Environment
    (JRE), which allows attackers to execute arbitrary code
    via (1) an untrusted object that extends the trusted
    class but has not modified a certain method, or (2) 'a
    similar trust issue with interfaces,' aka 'Trusted
    Methods Chaining Remote Code Execution Vulnerability.'.
    (CVE-2010-0840)

  - Unspecified vulnerability in the ImageIO component in
    Oracle Java SE and Java for Business 6 Update 18, 5.0
    Update 23, and 1.4.2_25 allows remote attackers to
    affect confidentiality, integrity, and availability via
    unknown vectors. NOTE: the previous information was
    obtained from the March 2010 CPU. Oracle has not
    commented on claims from a reliable researcher that this
    is an integer overflow in the Java Runtime Environment
    that allows remote attackers to execute arbitrary code
    via a JPEG image that contains subsample dimensions with
    large values, related to JPEGImageReader and 'stepX'.
    (CVE-2010-0841)

  - Unspecified vulnerability in the Sound component in
    Oracle Java SE and Java for Business 6 Update 18, 5.0
    Update 23, 1.4.225, and 1.3.1 27 allows remote attackers
    to affect confidentiality, integrity, and availability
    via unknown vectors. NOTE: the previous information was
    obtained from the March 2010 CPU. Oracle has not
    commented on claims from a reliable researcher that this
    is an uncontrolled array index that allows remote
    attackers to execute arbitrary code via a MIDI file with
    a crafted MixerSequencer object, related to the GM_Song
    structure. (CVE-2010-0842)

  - Unspecified vulnerability in the Sound component in
    Oracle Java SE and Java for Business 6 Update 18, 5.0
    Update 23, 1.4.225, and 1.3.1 27 allows remote attackers
    to affect confidentiality, integrity, and availability
    via unknown vectors. NOTE: the previous information was
    obtained from the March 2010 CPU. Oracle has not
    commented on claims from a reliable researcher that this
    is related to XNewPtr and improper handling of an
    integer parameter when allocating heap memory in the
    com.sun.media.sound libraries, which allows remote
    attackers to execute arbitrary code. (CVE-2010-0843)

  - Unspecified vulnerability in the Sound component in
    Oracle Java SE and Java for Business 6 Update 18, 5.0
    Update 23, 1.4.225, and 1.3.1 27 allows remote attackers
    to affect confidentiality, integrity, and availability
    via unknown vectors. NOTE: the previous information was
    obtained from the March 2010 CPU. Oracle has not
    commented on claims from a reliable researcher that this
    is for improper parsing of a crafted MIDI stream when
    creating a MixerSequencer object, which causes a pointer
    to be corrupted and allows a NULL byte to be written to
    arbitrary memory. (CVE-2010-0844)

  - Unspecified vulnerability in the ImageIO component in
    Oracle Java SE and Java for Business 6 Update 18, 5.0
    Update 23, 1.4.2_25, and 1.3.1_27 allows remote
    attackers to affect confidentiality, integrity, and
    availability via unknown vectors. NOTE: the previous
    information was obtained from the March 2010 CPU. Oracle
    has not commented on claims from a reliable researcher
    that this is a heap-based buffer overflow that allows
    remote attackers to execute arbitrary code, related to
    an 'invalid assignment' and inconsistent length values
    in a JPEG image encoder (JPEGImageEncoderImpl).
    (CVE-2010-0846)

  - Unspecified vulnerability in the Java 2D component in
    Oracle Java SE and Java for Business 6 Update 18, 5.0
    Update 23, 1.4.2_25, and 1.3.1_27 allows remote
    attackers to affect confidentiality, integrity, and
    availability via unknown vectors. NOTE: the previous
    information was obtained from the March 2010 CPU. Oracle
    has not commented on claims from a reliable researcher
    that this is a heap-based buffer overflow that allows
    arbitrary code execution via a crafted image.
    (CVE-2010-0847)

  - Unspecified vulnerability in the Java 2D component in
    Oracle Java SE and Java for Business 6 Update 18, 5.0
    Update 23, 1.4.2_25, and 1.3.1_27 allows remote
    attackers to affect confidentiality, integrity, and
    availability via unknown vectors. (CVE-2010-0848)

  - Unspecified vulnerability in the Java 2D component in
    Oracle Java SE and Java for Business 6 Update 18, 5.0
    Update 23, 1.4.2_25, and 1.3.1_27 allows remote
    attackers to affect confidentiality, integrity, and
    availability via unknown vectors. NOTE: the previous
    information was obtained from the March 2010 CPU. Oracle
    has not commented on claims from a reliable researcher
    that this is a heap-based buffer overflow in a decoding
    routine used by the JPEGImageDecoderImpl interface,
    which allows code execution via a crafted JPEG image.
    (CVE-2010-0849)

Please also see http://www.ibm.com/developerworks/java/jdk/alerts/ for
a more up to date list on what was fixed"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=603283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0084.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0085.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0087.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0088.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0089.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0090.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0091.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0092.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0094.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0095.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0837.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0838.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0839.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0840.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0841.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0842.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0843.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0844.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0846.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0847.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0848.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0849.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 2548.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java MixerSequencer Object GM_Song Structure Handling Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES11", sp:0, reference:"java-1_6_0-ibm-1.6.0_sr8.0-0.1.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"java-1_6_0-ibm-fonts-1.6.0_sr8.0-0.1.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"java-1_6_0-ibm-jdbc-1.6.0_sr8.0-0.1.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"java-1_6_0-ibm-alsa-1.6.0_sr8.0-0.1.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"java-1_6_0-ibm-plugin-1.6.0_sr8.0-0.1.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
