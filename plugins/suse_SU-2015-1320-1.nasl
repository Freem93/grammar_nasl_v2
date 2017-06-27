#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1320-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(85153);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/27 20:14:33 $");

  script_cve_id("CVE-2015-2590", "CVE-2015-2596", "CVE-2015-2597", "CVE-2015-2601", "CVE-2015-2613", "CVE-2015-2619", "CVE-2015-2621", "CVE-2015-2625", "CVE-2015-2627", "CVE-2015-2628", "CVE-2015-2632", "CVE-2015-2637", "CVE-2015-2638", "CVE-2015-2664", "CVE-2015-2808", "CVE-2015-4000", "CVE-2015-4729", "CVE-2015-4731", "CVE-2015-4732", "CVE-2015-4733", "CVE-2015-4736", "CVE-2015-4748", "CVE-2015-4749", "CVE-2015-4760");
  script_bugtraq_id(73684, 74733, 75784, 75796, 75812, 75818, 75823, 75832, 75833, 75850, 75854, 75856, 75857, 75861, 75867, 75871, 75874, 75881, 75883, 75887, 75890, 75892, 75893, 75895);
  script_osvdb_id(117855, 122331, 124489, 124617, 124618, 124619, 124620, 124621, 124622, 124623, 124624, 124625, 124626, 124627, 124628, 124629, 124630, 124631, 124633, 124634, 124635, 124636, 124637, 124638, 124639);

  script_name(english:"SUSE SLED11 Security Update : java-1_7_0-openjdk (SUSE-SU-2015:1320-1) (Bar Mitzvah) (Logjam)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"OpenJDK was updated to 2.6.1 - OpenJDK 7u85 to fix security issues and
bugs.

The following vulnerabilities were fixed :

  - CVE-2015-2590: Easily exploitable vulnerability in the
    Libraries component allowed successful unauthenticated
    network attacks via multiple protocols. Successful
    attack of this vulnerability could have resulted in
    unauthorized Operating System takeover including
    arbitrary code execution.

  - CVE-2015-2596: Difficult to exploit vulnerability in the
    Hotspot component allowed successful unauthenticated
    network attacks via multiple protocols. Successful
    attack of this vulnerability could have resulted in
    unauthorized update, insert or delete access to some
    Java accessible data.

  - CVE-2015-2597: Easily exploitable vulnerability in the
    Install component requiring logon to Operating System.
    Successful attack of this vulnerability could have
    resulted in unauthorized Operating System takeover
    including arbitrary code execution.

  - CVE-2015-2601: Easily exploitable vulnerability in the
    JCE component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    read access to a subset of Java accessible data.

  - CVE-2015-2613: Easily exploitable vulnerability in the
    JCE component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    read access to a subset of Java SE, Java SE Embedded
    accessible data.

  - CVE-2015-2619: Easily exploitable vulnerability in the
    2D component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    read access to a subset of Java accessible data.

  - CVE-2015-2621: Easily exploitable vulnerability in the
    JMX component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    read access to a subset of Java accessible data.

  - CVE-2015-2625: Very difficult to exploit vulnerability
    in the JSSE component allowed successful unauthenticated
    network attacks via SSL/TLS. Successful attack of this
    vulnerability could have resulted in unauthorized read
    access to a subset of Java accessible data.

  - CVE-2015-2627: Very difficult to exploit vulnerability
    in the Install component allowed successful
    unauthenticated network attacks via multiple protocols.
    Successful attack of this vulnerability could have
    resulted in unauthorized read access to a subset of Java
    accessible data.

  - CVE-2015-2628: Easily exploitable vulnerability in the
    CORBA component allowed successful unauthenticated
    network attacks via multiple protocols. Successful
    attack of this vulnerability could have resulted in
    unauthorized Operating System takeover including
    arbitrary code execution.

  - CVE-2015-2632: Easily exploitable vulnerability in the
    2D component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    read access to a subset of Java accessible data.

  - CVE-2015-2637: Easily exploitable vulnerability in the
    2D component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    read access to a subset of Java accessible data.

  - CVE-2015-2638: Easily exploitable vulnerability in the
    2D component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    Operating System takeover including arbitrary code
    execution.

  - CVE-2015-2664: Difficult to exploit vulnerability in the
    Deployment component requiring logon to Operating
    System. Successful attack of this vulnerability could
    have resulted in unauthorized Operating System takeover
    including arbitrary code execution.

  - CVE-2015-2808: Very difficult to exploit vulnerability
    in the JSSE component allowed successful unauthenticated
    network attacks via SSL/TLS. Successful attack of this
    vulnerability could have resulted in unauthorized
    update, insert or delete access to some Java accessible
    data as well as read access to a subset of Java
    accessible data.

  - CVE-2015-4000: Very difficult to exploit vulnerability
    in the JSSE component allowed successful unauthenticated
    network attacks via SSL/TLS. Successful attack of this
    vulnerability could have resulted in unauthorized
    update, insert or delete access to some Java accessible
    data as well as read access to a subset of Java Embedded
    accessible data.

  - CVE-2015-4729: Very difficult to exploit vulnerability
    in the Deployment component allowed successful
    unauthenticated network attacks via multiple protocols.
    Successful attack of this vulnerability could have
    resulted in unauthorized update, insert or delete access
    to some Java SE accessible data as well as read access
    to a subset of Java SE accessible data.

  - CVE-2015-4731: Easily exploitable vulnerability in the
    JMX component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    Operating System takeover including arbitrary code
    execution.

  - CVE-2015-4732: Easily exploitable vulnerability in the
    Libraries component allowed successful unauthenticated
    network attacks via multiple protocols. Successful
    attack of this vulnerability could have resulted in
    unauthorized Operating System takeover including
    arbitrary code execution.

  - CVE-2015-4733: Easily exploitable vulnerability in the
    RMI component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    Operating System takeover including arbitrary code
    execution.

  - CVE-2015-4736: Difficult to exploit vulnerability in the
    Deployment component allowed successful unauthenticated
    network attacks via multiple protocols. Successful
    attack of this vulnerability could have resulted in
    unauthorized Operating System takeover including
    arbitrary code execution.

  - CVE-2015-4748: Very difficult to exploit vulnerability
    in the Security component allowed successful
    unauthenticated network attacks via OCSP. Successful
    attack of this vulnerability could have resulted in
    unauthorized Operating System takeover including
    arbitrary code execution.

  - CVE-2015-4749: Difficult to exploit vulnerability in the
    JNDI component allowed successful unauthenticated
    network attacks via multiple protocols. Successful
    attack of this vulnerability could have resulted in
    unauthorized ability to cause a partial denial of
    service (partial DOS).

  - CVE-2015-4760: Easily exploitable vulnerability in the
    2D component allowed successful unauthenticated network
    attacks via multiple protocols. Successful attack of
    this vulnerability could have resulted in unauthorized
    Operating System takeover including arbitrary code
    execution.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/938248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2590.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2596.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2597.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2601.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2613.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2619.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2621.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2625.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2627.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2628.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2632.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2637.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2638.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2664.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2808.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4729.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4731.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4732.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4733.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4736.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4748.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4749.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4760.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151320-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a340dff"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-java-1_7_0-openjdk-12012=1

SUSE Linux Enterprise Desktop 11-SP3 :

zypper in -t patch sledsp3-java-1_7_0-openjdk-12012=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-java-1_7_0-openjdk-12012=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-java-1_7_0-openjdk-12012=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED11" && (! ereg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"java-1_7_0-openjdk-1.7.0.85-0.11.2")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"java-1_7_0-openjdk-demo-1.7.0.85-0.11.2")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"java-1_7_0-openjdk-devel-1.7.0.85-0.11.2")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"java-1_7_0-openjdk-1.7.0.85-0.11.2")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"java-1_7_0-openjdk-demo-1.7.0.85-0.11.2")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"java-1_7_0-openjdk-devel-1.7.0.85-0.11.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"java-1_7_0-openjdk-1.7.0.85-0.11.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"java-1_7_0-openjdk-demo-1.7.0.85-0.11.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"java-1_7_0-openjdk-devel-1.7.0.85-0.11.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"java-1_7_0-openjdk-1.7.0.85-0.11.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"java-1_7_0-openjdk-demo-1.7.0.85-0.11.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"java-1_7_0-openjdk-devel-1.7.0.85-0.11.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_7_0-openjdk");
}
