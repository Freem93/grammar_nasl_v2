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
  script_id(79635);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/13 15:30:41 $");

  script_cve_id("CVE-2014-3065", "CVE-2014-3566", "CVE-2014-4288", "CVE-2014-6456", "CVE-2014-6457", "CVE-2014-6458", "CVE-2014-6466", "CVE-2014-6476", "CVE-2014-6492", "CVE-2014-6493", "CVE-2014-6502", "CVE-2014-6503", "CVE-2014-6506", "CVE-2014-6511", "CVE-2014-6512", "CVE-2014-6513", "CVE-2014-6515", "CVE-2014-6527", "CVE-2014-6531", "CVE-2014-6532", "CVE-2014-6558");

  script_name(english:"SuSE 11.3 Security Update : IBM Java (SAT Patch Number 9999)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"java-1_7_0-ibm has been updated to version 1.7.0_sr7.2 to fix 21
security issues.

These security issues have been fixed :

  - Unspecified vulnerability. (CVE-2014-3065)

  - The SSL protocol 3.0, as used in OpenSSL through 1.0.1i
    and other products, uses nondeterministic CBC padding,
    which makes it easier for man-in-the-middle attackers to
    obtain cleartext data via a padding-oracle attack, aka
    the 'POODLE' issue. (CVE-2014-3566)

  - Unspecified vulnerability in Oracle Java SE 6u81, 7u67,
    and 8u20, and Java SE Embedded 7u60, allows remote
    attackers to affect confidentiality, integrity, and
    availability via vectors related to AWT. (CVE-2014-6513)

  - Unspecified vulnerability in Oracle Java SE 7u67 and
    8u20 allows remote attackers to affect confidentiality,
    integrity, and availability via unknown vectors.
    (CVE-2014-6456)

  - Unspecified vulnerability in Oracle Java SE 6u81, 7u67,
    and 8u20 allows remote attackers to affect
    confidentiality, integrity, and availability via unknown
    vectors related to Deployment, a different vulnerability
    than CVE-2014-4288 / CVE-2014-6493 / CVE-2014-6532.
    (CVE-2014-6503)

  - Unspecified vulnerability in Oracle Java SE 6u81, 7u67,
    and 8u20 allows remote attackers to affect
    confidentiality, integrity, and availability via unknown
    vectors related to Deployment, a different vulnerability
    than CVE-2014-4288 / CVE-2014-6493 / CVE-2014-6503.
    (CVE-2014-6532)

  - Unspecified vulnerability in Oracle Java SE 6u81, 7u67,
    and 8u20 allows remote attackers to affect
    confidentiality, integrity, and availability via unknown
    vectors related to Deployment, a different vulnerability
    than CVE-2014-6493 / CVE-2014-6503 / CVE-2014-6532.
    (CVE-2014-4288)

  - Unspecified vulnerability in Oracle Java SE 6u81, 7u67,
    and 8u20 allows remote attackers to affect
    confidentiality, integrity, and availability via unknown
    vectors related to Deployment, a different vulnerability
    than CVE-2014-4288 / CVE-2014-6503 / CVE-2014-6532.
    (CVE-2014-6493)

  - Unspecified vulnerability in Oracle Java SE 6u81, 7u67,
    and 8u20, when running on Firefox, allows remote
    attackers to affect confidentiality, integrity, and
    availability via unknown vectors related to Deployment.
    (CVE-2014-6492)

  - Unspecified vulnerability in Oracle Java SE 6u81, 7u67,
    and 8u20 allows local users to affect confidentiality,
    integrity, and availability via unknown vectors related
    to Deployment. (CVE-2014-6458)

  - Unspecified vulnerability in Oracle Java SE 6u81, 7u67,
    and 8u20, when running on Internet Explorer, allows
    local users to affect confidentiality, integrity, and
    availability via unknown vectors related to Deployment.
    (CVE-2014-6466)

  - Unspecified vulnerability in Oracle Java SE 5.0u71,
    6u81, 7u67, and 8u20, and Java SE Embedded 7u60, allows
    remote attackers to affect confidentiality, integrity,
    and availability via unknown vectors related to
    Libraries. (CVE-2014-6506)

  - Unspecified vulnerability in Oracle Java SE 7u67 and
    8u20 allows remote attackers to affect integrity via
    unknown vectors related to Deployment, a different
    vulnerability than CVE-2014-6527. (CVE-2014-6476)

  - Unspecified vulnerability in Oracle Java SE 6u81, 7u67,
    and 8u20 allows remote attackers to affect integrity via
    unknown vectors related to Deployment. (CVE-2014-6515)

  - Unspecified vulnerability in Oracle Java SE 5.0u71,
    6u81, 7u67, and 8u20 allows remote attackers to affect
    confidentiality via unknown vectors related to 2D.
    (CVE-2014-6511)

  - Unspecified vulnerability in Oracle Java SE 5.0u71,
    6u81, 7u67, and 8u20, and Java SE Embedded 7u60, allows
    remote attackers to affect confidentiality via unknown
    vectors related to Libraries. (CVE-2014-6531)

  - Unspecified vulnerability in Oracle Java SE 5.0u71,
    6u81, 7u67, and 8u20; Java SE Embedded 7u60; and JRockit
    R27.8.3 and R28.3.3 allows remote attackers to affect
    integrity via unknown vectors related to Libraries.
    (CVE-2014-6512)

  - Unspecified vulnerability in Oracle Java SE 5.0u71,
    6u81, 7u67, and 8u20; Java SE Embedded 7u60; and JRockit
    R27.8.3, and R28.3.3 allows remote attackers to affect
    confidentiality and integrity via vectors related to
    JSSE. (CVE-2014-6457)

  - Unspecified vulnerability in Oracle Java SE 7u67 and
    8u20 allows remote attackers to affect integrity via
    unknown vectors related to Deployment, a different
    vulnerability than CVE-2014-6476. (CVE-2014-6527)

  - Unspecified vulnerability in Oracle Java SE 5.0u71,
    6u81, 7u67, and 8u20, and Java SE Embedded 7u60, allows
    remote attackers to affect integrity via unknown vectors
    related to Libraries. (CVE-2014-6502)

  - Unspecified vulnerability in Oracle Java SE 5.0u71,
    6u81, 7u67, and 8u20; Java SE Embedded 7u60; and JRockit
    R27.8.3 and JRockit R28.3.3 allows remote attackers to
    affect integrity via unknown vectors related to
    Security. (CVE-2014-6558)

More information can be found at
http://www.ibm.com/developerworks/java/jdk/alerts/#IBM_Security_Update
_November_2014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=904889"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3065.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3566.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4288.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6456.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6457.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6458.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6466.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6476.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6492.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6493.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6502.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6503.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6506.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6511.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6512.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6513.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6515.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6527.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6531.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6532.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6558.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 9999.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_7_0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_7_0-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_7_0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_7_0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLES11", sp:3, reference:"java-1_7_0-ibm-1.7.0_sr8.0-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"java-1_7_0-ibm-jdbc-1.7.0_sr8.0-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"java-1_7_0-ibm-alsa-1.7.0_sr8.0-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"java-1_7_0-ibm-plugin-1.7.0_sr8.0-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"java-1_7_0-ibm-alsa-1.7.0_sr8.0-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"java-1_7_0-ibm-plugin-1.7.0_sr8.0-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
