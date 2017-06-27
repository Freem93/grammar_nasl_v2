#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50896);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/10/25 23:41:52 $");

  script_cve_id("CVE-2010-0098", "CVE-2010-1311");

  script_name(english:"SuSE 11 Security Update : clamav (SAT Patch Number 2298)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Specially crafted CAB archives could crash clamav (CVE-2010-1311) or
bypass virus detection (CVE-2010-0098). clamav has been updated to
version 0.96 which fixes those issues.

Citing freshmeat.net :

This Release introduces new malware detection mechanisms and other
significant improvements to the scan engine. Key features include the
bytecode interpreter, heuristic improvements, signature improvements,
support for new archives, support for new executable file formats,
support for UPX 3.0, performance improvements and memory
optimizations."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=587363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0098.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1311.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 2298.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libgcc43");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libgcc43-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/14");
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
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"clamav-0.96-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"libgcc43-4.3.3_20081022-11.18")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"clamav-0.96-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libgcc43-4.3.3_20081022-11.18")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libgcc43-32bit-4.3.3_20081022-11.18")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"clamav-0.96-0.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"libgcc43-4.3.3_20081022-11.18")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"libgcc43-32bit-4.3.3_20081022-11.18")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"libgcc43-32bit-4.3.3_20081022-11.18")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
