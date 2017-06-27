#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(49864);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/11/18 01:35:31 $");

  script_cve_id("CVE-2009-3555", "CVE-2010-0084", "CVE-2010-0085", "CVE-2010-0087", "CVE-2010-0088", "CVE-2010-0089", "CVE-2010-0091", "CVE-2010-0092", "CVE-2010-0094", "CVE-2010-0095", "CVE-2010-0837", "CVE-2010-0838", "CVE-2010-0839", "CVE-2010-0840", "CVE-2010-0841", "CVE-2010-0842", "CVE-2010-0843", "CVE-2010-0844", "CVE-2010-0846", "CVE-2010-0847", "CVE-2010-0848", "CVE-2010-0849");

  script_name(english:"SuSE 10 Security Update : IBM Java 1.5.0 (ZYPP Patch Number 7077)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of IBM Java 1.5.0 to SR11 FP2 to fixes the following
security issues :

  - Various unspecified and undocumented vulnerabilities
    that allows remote attackers to affect confidentiality,
    integrity and availability via various unknown vectors.
    (CVE-2010-0084 / CVE-2010-0085 / CVE-2010-0087 /
    CVE-2010-0088 / CVE-2010-0089 / CVE-2010-0091 /
    CVE-2010-0092 / CVE-2010-0095 / CVE-2010-0837 /
    CVE-2010-0839)

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

  - The TLS protocol, and the SSL protocol 3.0 and possibly
    earlier, as used in Microsoft Internet Information
    Services (IIS) 7.0, mod_ssl in the Apache HTTP Server
    2.2.14 and earlier, OpenSSL before 0.9.8l, GnuTLS 2.8.5
    and earlier, Mozilla Network Security Services (NSS)
    3.12.4 and earlier, multiple Cisco products, and other
    products, does not properly associate renegotiation
    handshakes with an existing connection, which allows
    man-in-the-middle attackers to insert data into HTTPS
    sessions, and possibly other types of sessions protected
    by TLS or SSL, by sending an unauthenticated request
    that is processed retroactively by a server in a
    post-renegotiation context, related to a 'plaintext
    injection' attack, aka the 'Project Mogul' issue.
    (CVE-2009-3555). (CVE-2009-3555)

This update of IBM Java 1.5.0 to SR11 FP2 brings various bug and lots
of security fixes.

The following security issues were fixed: CVE-2010-0084: Unspecified
vulnerability in the Java Runtime Environment component in Oracle Java
SE and Java for Business 6 Update 18, 5.0 Update 23, and 1.4.2_25
allows remote attackers to affect confidentiality via unknown vectors.

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

  - The TLS protocol, and the SSL protocol 3.0 and possibly
    earlier, as used in Microsoft Internet Information
    Services (IIS) 7.0, mod_ssl in the Apache HTTP Server
    2.2.14 and earlier, OpenSSL before 0.9.8l, GnuTLS 2.8.5
    and earlier, Mozilla Network Security Services (NSS)
    3.12.4 and earlier, multiple Cisco products, and other
    products, does not properly associate renegotiation
    handshakes with an existing connection, which allows
    man-in-the-middle attackers to insert data into HTTPS
    sessions, and possibly other types of sessions protected
    by TLS or SSL, by sending an unauthenticated request
    that is processed retroactively by a server in a
    post-renegotiation context, related to a 'plaintext
    injection' attack, aka the 'Project Mogul' issue.
    (CVE-2009-3555)

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
    functions via the ClassLoader of a constructor that is
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
    in the JVM. (CVE-2010-0838)

  - Unspecified vulnerability in the Sound component in
    Oracle Java SE and Java for Business 6 Update 18, 5.0
    Update 23, 1.4.225, and 1.3.127 allows remote attackers
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
    Update 23, 1.4.225, and 1.3.127 allows remote attackers
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
    Update 23, 1.4.225, and 1.3.127 allows remote attackers
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
    Update 23, 1.4.225, and 1.3.127 allows remote attackers
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
    (CVE-2010-0849)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3555.html"
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
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7077.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java MixerSequencer Object GM_Song Structure Handling Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:3, reference:"java-1_5_0-ibm-1.5.0_sr11.2-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"java-1_5_0-ibm-demo-1.5.0_sr11.2-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"java-1_5_0-ibm-devel-1.5.0_sr11.2-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"java-1_5_0-ibm-fonts-1.5.0_sr11.2-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"java-1_5_0-ibm-src-1.5.0_sr11.2-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"java-1_5_0-ibm-alsa-1.5.0_sr11.2-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"java-1_5_0-ibm-jdbc-1.5.0_sr11.2-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"java-1_5_0-ibm-plugin-1.5.0_sr11.2-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"java-1_5_0-ibm-32bit-1.5.0_sr11.2-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"java-1_5_0-ibm-alsa-32bit-1.5.0_sr11.2-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"java-1_5_0-ibm-devel-32bit-1.5.0_sr11.2-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"java-1_5_0-ibm-1.5.0_sr11.2-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"java-1_5_0-ibm-devel-1.5.0_sr11.2-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"java-1_5_0-ibm-fonts-1.5.0_sr11.2-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"java-1_5_0-ibm-alsa-1.5.0_sr11.2-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"java-1_5_0-ibm-jdbc-1.5.0_sr11.2-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"java-1_5_0-ibm-plugin-1.5.0_sr11.2-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"java-1_5_0-ibm-32bit-1.5.0_sr11.2-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"java-1_5_0-ibm-alsa-32bit-1.5.0_sr11.2-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"java-1_5_0-ibm-devel-32bit-1.5.0_sr11.2-0.4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
