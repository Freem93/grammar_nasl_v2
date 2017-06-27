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
  script_id(50937);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/21 20:21:20 $");

  script_cve_id("CVE-2009-3245", "CVE-2009-3555");

  script_name(english:"SuSE 11 Security Update : OpenSSL (SAT Patch Number 2214)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update adds support for RFC5746 TLS renegotiations to address
vulnerabilities tracked as (CVE-2009-3555). It also fixes a
mishandling of OOM conditions in bn_wexpand. (CVE-2009-3245)

Installation notes

This update is provided as RPM packages that can easily be installed
onto a running system by using this command :

rpm -Fvh libopenssl-devel.rpm libopenssl0_9_8.rpm
libopenssl0_9_8-32bit.rpm libopenssl0_9_8-x86.rpm openssl.rpm
openssl-debuginfo.rpm openssl-debugsource.rpm openssl-doc.rpm"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=584292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3245.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3555.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 2214.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libopenssl0_9_8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libopenssl0_9_8-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:openssl-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"libopenssl0_9_8-0.9.8h-30.22.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"openssl-0.9.8h-30.22.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libopenssl0_9_8-0.9.8h-30.22.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libopenssl0_9_8-32bit-0.9.8h-30.22.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"openssl-0.9.8h-30.22.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"libopenssl0_9_8-0.9.8h-30.22.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"openssl-0.9.8h-30.22.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"openssl-doc-0.9.8h-30.22.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"libopenssl0_9_8-32bit-0.9.8h-30.22.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"libopenssl0_9_8-32bit-0.9.8h-30.22.21.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
