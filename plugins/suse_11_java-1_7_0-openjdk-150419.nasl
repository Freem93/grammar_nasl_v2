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
  script_id(83287);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/08 13:26:40 $");

  script_cve_id("CVE-2015-0458", "CVE-2015-0459", "CVE-2015-0460", "CVE-2015-0469", "CVE-2015-0477", "CVE-2015-0478", "CVE-2015-0480", "CVE-2015-0484", "CVE-2015-0488", "CVE-2015-0491", "CVE-2015-0492");

  script_name(english:"SuSE 11.3 Security Update : java-1_7_0-openjdk (SAT Patch Number 10621)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"OpenJDK was updated to version 2.5.5 - OpenJDK 7u79 to fix security
issues and bugs.

The following vulnerabilities have been fixed :

  - Deployment: unauthenticated remote attackers could
    execute arbitrary code via multiple protocols.
    (CVE-2015-0458)

  - 2D: unauthenticated remote attackers could execute
    arbitrary code via multiple protocols. (CVE-2015-0459)

  - Hotspot: unauthenticated remote attackers could execute
    arbitrary code via multiple protocols. (CVE-2015-0460)

  - 2D: unauthenticated remote attackers could execute
    arbitrary code via multiple protocols. (CVE-2015-0469)

  - Beans: unauthenticated remote attackers could update,
    insert or delete some JAVA accessible data via multiple
    protocols. (CVE-2015-0477)

  - JCE: unauthenticated remote attackers could read some
    JAVA accessible data via multiple protocols.
    (CVE-2015-0478)

  - Tools: unauthenticated remote attackers could update,
    insert or delete some JAVA accessible data via multiple
    protocols and cause a partial denial of service (partial
    DOS). (CVE-2015-0480)

  - JavaFX: unauthenticated remote attackers could read,
    update, insert or delete access some Java accessible
    data via multiple protocols and cause a partial denial
    of service (partial DOS). (CVE-2015-0484)

  - JSSE: unauthenticated remote attackers could cause a
    partial denial of service (partial DOS). (CVE-2015-0488)

  - 2D: unauthenticated remote attackers could execute
    arbitrary code via multiple protocols. (CVE-2015-0491)

  - JavaFX: unauthenticated remote attackers could execute
    arbitrary code via multiple protocols. (CVE-2015-0492)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=927591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0458.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0459.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0460.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0469.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0477.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0478.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0480.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0484.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0488.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0491.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0492.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 10621.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_7_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_7_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:java-1_7_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"java-1_7_0-openjdk-1.7.0.75-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"java-1_7_0-openjdk-demo-1.7.0.75-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"java-1_7_0-openjdk-devel-1.7.0.75-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"java-1_7_0-openjdk-1.7.0.75-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"java-1_7_0-openjdk-demo-1.7.0.75-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"java-1_7_0-openjdk-devel-1.7.0.75-0.9.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
