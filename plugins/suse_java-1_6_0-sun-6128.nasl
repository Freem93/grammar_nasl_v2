#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update java-1_6_0-sun-6128.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(36071);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2009-1093", "CVE-2009-1094", "CVE-2009-1095", "CVE-2009-1096", "CVE-2009-1097", "CVE-2009-1098", "CVE-2009-1099", "CVE-2009-1100", "CVE-2009-1101", "CVE-2009-1102", "CVE-2009-1103", "CVE-2009-1104", "CVE-2009-1105", "CVE-2009-1106", "CVE-2009-1107");

  script_name(english:"openSUSE 10 Security Update : java-1_6_0-sun (java-1_6_0-sun-6128)");
  script_summary(english:"Check for the java-1_6_0-sun-6128 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Sun JDK 6 was updated to Update13 to fix various bugs and security
issues.

CVE-2009-1093: LdapCtx in the LDAP service in Java SE Development Kit
(JDK) and Java Runtime Environment (JRE) 5.0 Update 17 and earlier; 6
Update 12 and earlier; SDK and JRE 1.3.1_24 and earlier; and 1.4.2_19
and earlier does not close the connection when initialization fails,
which allows remote attackers to cause a denial of service (LDAP
service hang).

CVE-2009-1094: Unspecified vulnerability in the LDAP implementation in
Java SE Development Kit (JDK) and Java Runtime Environment (JRE) 5.0
Update 17 and earlier; 6 Update 12 and earlier; SDK and JRE 1.3.1_24
and earlier; and 1.4.2_19 and earlier allows remote LDAP servers to
execute arbitrary code via unknown vectors related to serialized data.

CVE-2009-1095: Integer overflow in unpack200 in Java SE Development
Kit (JDK) and Java Runtime Environment (JRE) 5.0 Update 17 and
earlier, and 6 Update 12 and earlier, allows remote attackers to
access files or execute arbitrary code via a JAR file with crafted
Pack200 headers.

CVE-2009-1096: Buffer overflow in unpack200 in Java SE Development Kit
(JDK) and Java Runtime Environment (JRE) 5.0 Update 17 and earlier,
and 6 Update 12 and earlier, allows remote attackers to access files
or execute arbitrary code via a JAR file with crafted Pack200 headers.

CVE-2009-1097: Multiple buffer overflows in Java SE Development Kit
(JDK) and Java Runtime Environment (JRE) 6 Update 12 and earlier allow
remote attackers to access files or execute arbitrary code via a
crafted (1) PNG image, aka CR 6804996, and (2) GIF image, aka CR
6804997.

CVE-2009-1098: Buffer overflow in Java SE Development Kit (JDK) and
Java Runtime Environment (JRE) 5.0 Update 17 and earlier; 6 Update 12
and earlier; 1.4.2_19 and earlier; and 1.3.1_24 and earlier allows
remote attackers to access files or execute arbitrary code via a
crafted GIF image, aka CR 6804998.

CVE-2009-1099: Integer signedness error in Java SE Development Kit
(JDK) and Java Runtime Environment (JRE) 5.0 Update 17 and earlier,
and 6 Update 12 and earlier, allows remote attackers to access files
or execute arbitrary code via a crafted Type1 font, which triggers a
buffer overflow.

CVE-2009-1100: Multiple unspecified vulnerabilities in Java SE
Development Kit (JDK) and Java Runtime Environment (JRE) 5.0 Update 17
and earlier, and 6 Update 12 and earlier, allow remote attackers to
cause a denial of service (disk consumption) via vectors related to
temporary font files and (1) 'limits on Font creation,' aka CR
6522586, and (2) another unspecified vector, aka CR 6632886.

CVE-2009-1101: Unspecified vulnerability in the lightweight HTTP
server implementation in Java SE Development Kit (JDK) and Java
Runtime Environment (JRE) 6 Update 12 and earlier allows remote
attackers to cause a denial of service (probably resource consumption)
for a JAX-WS service endpoint via a connection without any data, which
triggers a file descriptor 'leak.'

CVE-2009-1102: Unspecified vulnerability in the Virtual Machine in
Java SE Development Kit (JDK) and Java Runtime Environment (JRE) 6
Update 12 and earlier allows remote attackers to access files and
execute arbitrary code via unknown vectors related to 'code
generation.'

CVE-2009-1103: Unspecified vulnerability in the Java Plug-in in Java
SE Development Kit (JDK) and Java Runtime Environment (JRE) 5.0 Update
17 and earlier; 6 Update 12 and earlier; 1.4.2_19 and earlier; and
1.3.1_24 and earlier allows remote attackers to access files and
execute arbitrary code via unknown vectors related to 'deserializing
applets,' aka CR 6646860.

CVE-2009-1104: The Java Plug-in in Java SE Development Kit (JDK) and
Java Runtime Environment (JRE) 5.0 Update 17 and earlier; 6 Update 12
and earlier; and 1.4.2_19 and earlier does not prevent JavaScript that
is loaded from the localhost from connecting to other ports on the
system, which allows user-assisted attackers to bypass intended access
restrictions via LiveConnect, aka CR 6724331. NOTE: this vulnerability
can be leveraged with separate cross-site scripting (XSS)
vulnerabilities for remote attack vectors.

CVE-2009-1105: The Java Plug-in in Java SE Development Kit (JDK) and
Java Runtime Environment (JRE) 6 Update 12, 11, and 10 allows
user-assisted remote attackers to cause a trusted applet to run in an
older JRE version, which can be used to exploit vulnerabilities in
that older version, aka CR 6706490.

CVE-2009-1106: The Java Plug-in in Java SE Development Kit (JDK) and
Java Runtime Environment (JRE) 6 Update 12, 11, and 10 does not
properly parse crossdomain.xml files, which allows remote attackers to
bypass intended access restrictions and connect to arbitrary sites via
unknown vectors, aka CR 6798948.

CVE-2009-1107: The Java Plug-in in Java SE Development Kit (JDK) and
Java Runtime Environment (JRE) 6 Update 12 and earlier, and 5.0 Update
17 and earlier, allows remote attackers to trick a user into trusting
a signed applet via unknown vectors that misrepresent the security
warning dialog, related to a 'Swing JLabel HTML parsing
vulnerability,' aka CR 6782871."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_6_0-sun packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(16, 20, 94, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.3", reference:"java-1_6_0-sun-1.6.0.u12-1.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"java-1_6_0-sun-alsa-1.6.0.u12-1.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"java-1_6_0-sun-debuginfo-1.6.0.u12-1.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"java-1_6_0-sun-demo-1.6.0.u12-1.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"java-1_6_0-sun-devel-1.6.0.u12-1.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"java-1_6_0-sun-jdbc-1.6.0.u12-1.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"java-1_6_0-sun-plugin-1.6.0.u12-1.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"java-1_6_0-sun-src-1.6.0.u12-1.4") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_6_0-sun");
}
