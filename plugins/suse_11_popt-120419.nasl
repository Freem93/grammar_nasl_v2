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
  script_id(64213);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/10/25 23:52:02 $");

  script_cve_id("CVE-2012-0060", "CVE-2012-0061", "CVE-2012-0815");

  script_name(english:"SuSE 11.1 Security Update : RPM (SAT Patch Number 6186)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security vulnerabilities were reported in RPM which could be
exploited via specially crafted RPM files to cause a denial of service
(application crash) or potentially allow attackers to execute
arbitrary code.

Additionally, a non-security issue was fixed that could cause a
division by zero in cycles calculation under rare circumstances."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=747225"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=754281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=754284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=754285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0060.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0061.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0815.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 6186.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:popt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:popt-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:rpm-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
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
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"popt-1.7-37.29.33.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"rpm-4.4.2.3-37.29.33.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"popt-1.7-37.29.33.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"popt-32bit-1.7-37.29.33.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"rpm-4.4.2.3-37.29.33.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"rpm-32bit-4.4.2.3-37.29.33.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"popt-1.7-37.29.33.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"rpm-4.4.2.3-37.29.33.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"popt-32bit-1.7-37.29.33.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"rpm-32bit-4.4.2.3-37.29.33.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"popt-32bit-1.7-37.29.33.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"rpm-32bit-4.4.2.3-37.29.33.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
