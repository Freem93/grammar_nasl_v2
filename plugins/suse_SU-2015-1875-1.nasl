#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1875-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(86707);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/05/02 15:19:32 $");

  script_cve_id("CVE-2015-4734", "CVE-2015-4803", "CVE-2015-4805", "CVE-2015-4806", "CVE-2015-4835", "CVE-2015-4840", "CVE-2015-4842", "CVE-2015-4843", "CVE-2015-4844", "CVE-2015-4860", "CVE-2015-4872", "CVE-2015-4881", "CVE-2015-4882", "CVE-2015-4883", "CVE-2015-4893", "CVE-2015-4903", "CVE-2015-4911");
  script_osvdb_id(129119, 129120, 129121, 129122, 129123, 129124, 129125, 129129, 129132, 129133, 129134, 129135, 129136, 129137, 129138, 129139, 129140);

  script_name(english:"SUSE SLED11 Security Update : java-1_7_0-openjdk (SUSE-SU-2015:1875-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"java-1_7_0-openjdk was updated to version 7u91 to fix 17 security
issues.

These security issues were fixed :

  - CVE-2015-4843: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60, and Java SE Embedded 8u51,
    allowed remote attackers to affect confidentiality,
    integrity, and availability via unknown vectors related
    to Libraries (bsc#951376).

  - CVE-2015-4842: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60, and Java SE Embedded 8u51,
    allowed remote attackers to affect confidentiality via
    vectors related to JAXP (bsc#951376).

  - CVE-2015-4840: Unspecified vulnerability in Oracle Java
    SE 7u85 and 8u60, and Java SE Embedded 8u51, allowed
    remote attackers to affect confidentiality via unknown
    vectors related to 2D (bsc#951376).

  - CVE-2015-4872: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60; Java SE Embedded 8u51; and
    JRockit R28.3.7 allowed remote attackers to affect
    integrity via unknown vectors related to Security
    (bsc#951376).

  - CVE-2015-4860: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60, and Java SE Embedded 8u51,
    allowed remote attackers to affect confidentiality,
    integrity, and availability via vectors related to RMI,
    a different vulnerability than CVE-2015-4883
    (bsc#951376).

  - CVE-2015-4844: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60, and Java SE Embedded 8u51,
    allowed remote attackers to affect confidentiality,
    integrity, and availability via unknown vectors related
    to 2D (bsc#951376).

  - CVE-2015-4883: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60, and Java SE Embedded 8u51,
    allowed remote attackers to affect confidentiality,
    integrity, and availability via vectors related to RMI,
    a different vulnerability than CVE-2015-4860
    (bsc#951376).

  - CVE-2015-4893: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60; Java SE Embedded 8u51; and
    JRockit R28.3.7 allowed remote attackers to affect
    availability via vectors related to JAXP, a different
    vulnerability than CVE-2015-4803 and CVE-2015-4911
    (bsc#951376).

  - CVE-2015-4911: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60; Java SE Embedded 8u51; and
    JRockit R28.3.7 allowed remote attackers to affect
    availability via vectors related to JAXP, a different
    vulnerability than CVE-2015-4803 and CVE-2015-4893
    (bsc#951376).

  - CVE-2015-4882: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60, and Java SE Embedded 8u51,
    allowed remote attackers to affect availability via
    vectors related to CORBA (bsc#951376).

  - CVE-2015-4881: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60, and Java SE Embedded 8u51,
    allowed remote attackers to affect confidentiality,
    integrity, and availability via vectors related to
    CORBA, a different vulnerability than CVE-2015-4835
    (bsc#951376).

  - CVE-2015-4734: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85 and 8u60, and Java SE Embedded 8u51,
    allowed remote attackers to affect confidentiality via
    vectors related to JGSS (bsc#951376).

  - CVE-2015-4806: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60, and Java SE Embedded 8u51,
    allowed remote attackers to affect confidentiality and
    integrity via unknown vectors related to Libraries
    (bsc#951376).

  - CVE-2015-4805: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60, and Java SE Embedded 8u51,
    allowed remote attackers to affect confidentiality,
    integrity, and availability via unknown vectors related
    to Serialization (bsc#951376).

  - CVE-2015-4803: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60; Java SE Embedded 8u51; and
    JRockit R28.3.7 allowed remote attackers to affect
    availability via vectors related to JAXP, a different
    vulnerability than CVE-2015-4893 and CVE-2015-4911
    (bsc#951376).

  - CVE-2015-4835: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60, and Java SE Embedded 8u51,
    allowed remote attackers to affect confidentiality,
    integrity, and availability via vectors related to
    CORBA, a different vulnerability than CVE-2015-4881
    (bsc#951376).

  - CVE-2015-4903: Unspecified vulnerability in Oracle Java
    SE 6u101, 7u85, and 8u60, and Java SE Embedded 8u51,
    allowed remote attackers to affect confidentiality via
    vectors related to RMI (bsc#951376).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4734.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4803.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4805.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4806.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4835.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4840.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4842.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4843.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4844.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4860.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4872.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4881.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4882.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4883.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4893.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4903.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4911.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151875-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?206787b4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-java-1_7_0-openjdk-12179=1

SUSE Linux Enterprise Desktop 11-SP3 :

zypper in -t patch sledsp3-java-1_7_0-openjdk-12179=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/03");
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
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"java-1_7_0-openjdk-1.7.0.91-0.14.2")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"java-1_7_0-openjdk-demo-1.7.0.91-0.14.2")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"java-1_7_0-openjdk-devel-1.7.0.91-0.14.2")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"java-1_7_0-openjdk-1.7.0.91-0.14.2")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"java-1_7_0-openjdk-demo-1.7.0.91-0.14.2")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"java-1_7_0-openjdk-devel-1.7.0.91-0.14.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"java-1_7_0-openjdk-1.7.0.91-0.14.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"java-1_7_0-openjdk-demo-1.7.0.91-0.14.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"java-1_7_0-openjdk-devel-1.7.0.91-0.14.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"java-1_7_0-openjdk-1.7.0.91-0.14.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"java-1_7_0-openjdk-demo-1.7.0.91-0.14.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"java-1_7_0-openjdk-devel-1.7.0.91-0.14.2")) flag++;


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
