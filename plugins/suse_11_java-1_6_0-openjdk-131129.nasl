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
  script_id(71171);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/12/03 12:13:22 $");

  script_cve_id("CVE-2013-3829", "CVE-2013-4002", "CVE-2013-5772", "CVE-2013-5774", "CVE-2013-5778", "CVE-2013-5780", "CVE-2013-5782", "CVE-2013-5783", "CVE-2013-5784", "CVE-2013-5790", "CVE-2013-5797", "CVE-2013-5802", "CVE-2013-5803", "CVE-2013-5804", "CVE-2013-5809", "CVE-2013-5814", "CVE-2013-5817", "CVE-2013-5820", "CVE-2013-5823", "CVE-2013-5825", "CVE-2013-5829", "CVE-2013-5830", "CVE-2013-5840", "CVE-2013-5842", "CVE-2013-5849", "CVE-2013-5850", "CVE-2013-5851");

  script_name(english:"SuSE 11.2 Security Update : OpenJDK 1.6 (SAT Patch Number 8598)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"OpenJDK 1.6 was updated to the new Icedtea release 1.12.7, which
includes many fixes for bugs and security issues :

  - S8006900, CVE-2013-3829: Add new date/time capability

  - S8008589: Better MBean permission validation

  - S8011071, CVE-2013-5780: Better crypto provider handling

  - S8011081, CVE-2013-5772: Improve jhat

  - S8011157, CVE-2013-5814: Improve CORBA portablility

  - S8012071, CVE-2013-5790: Better Building of Beans

  - S8012147: Improve tool support

  - S8012277: CVE-2013-5849: Improve AWT DataFlavor

  - S8012425, CVE-2013-5802: Transform TransformerFactory

  - S8013503, CVE-2013-5851: Improve stream factories

  - S8013506: Better Pack200 data handling

  - S8013510, CVE-2013-5809: Augment image writing code

  - S8013514: Improve stability of cmap class

  - S8013739, CVE-2013-5817: Better LDAP resource management

  - S8013744, CVE-2013-5783: Better tabling for AWT

  - S8014085: Better serialization support in JMX classes

  - S8014093, CVE-2013-5782: Improve parsing of images

  - S8014102, CVE-2013-5778: Improve image conversion

  - S8014341, CVE-2013-5803: Better service from Kerberos
    servers

  - S8014349, CVE-2013-5840: (cl) Class.getDeclaredClass
    problematic in some class loader configurations

  - S8014530, CVE-2013-5825: Better digital signature
    processing

  - S8014534: Better profiling support

  - S8014987, CVE-2013-5842: Augment serialization handling

  - S8015614: Update build settings

  - S8015731: Subject java.security.auth.subject to
    improvements

  - S8015743, CVE-2013-5774: Address internet addresses

  - S8016256: Make finalization final

  - S8016653, CVE-2013-5804: javadoc should ignore
    ignoreable characters in names

  - S8016675, CVE-2013-5797: Make Javadoc pages more robust

  - S8017196, CVE-2013-5850: Ensure Proxies are handled
    appropriately

  - S8017287, CVE-2013-5829: Better resource disposal

  - S8017291, CVE-2013-5830: Cast Proxies Aside

  - S8017298, CVE-2013-4002: Better XML support

  - S8017300, CVE-2013-5784: Improve Interface
    Implementation

  - S8017505, CVE-2013-5820: Better Client Service

  - S8019292: Better Attribute Value Exceptions

  - S8019617: Better view of objects

  - S8020293: JVM crash

  - S8021290, CVE-2013-5823: Better signature validation

  - S8022940: Enhance CORBA translations

  - S8023683: Enhance class file parsing"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=852367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3829.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5772.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5774.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5778.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5780.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5782.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5783.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5784.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5790.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5797.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5802.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5803.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5804.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5809.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5814.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5817.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5820.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5823.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5825.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5829.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5830.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5840.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5842.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5849.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5850.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5851.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 8598.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_6_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"java-1_6_0-openjdk-1.6.0.0_b27.1.12.7-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"java-1_6_0-openjdk-demo-1.6.0.0_b27.1.12.7-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"java-1_6_0-openjdk-devel-1.6.0.0_b27.1.12.7-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"java-1_6_0-openjdk-1.6.0.0_b27.1.12.7-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"java-1_6_0-openjdk-demo-1.6.0.0_b27.1.12.7-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"java-1_6_0-openjdk-devel-1.6.0.0_b27.1.12.7-0.2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
