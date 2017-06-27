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
  script_id(81666);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/06 14:56:53 $");

  script_cve_id("CVE-2014-9447");

  script_name(english:"SuSE 11.3 Security Update : elfutils (SAT Patch Number 10328)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"elfutils has been updated to fix one security issue :

  - Directory traversal vulnerability in the read_long_names
    function in libelf/elf_begin.c in elfutils 0.152 and
    0.161 allowed remote attackers to write to arbitrary
    files to the root directory via a / (slash) in a crafted
    archive, as demonstrated using the ar program.
    (bnc#911662). (CVE-2014-9447)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=911662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9447.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 10328.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:elfutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libasm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libasm1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libdw1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libdw1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libebl1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libebl1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libelf1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libelf1-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/06");
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
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"elfutils-0.152-4.9.17")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libasm1-0.152-4.9.17")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libdw1-0.152-4.9.17")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libebl1-0.152-4.9.17")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libelf1-0.152-4.9.17")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"elfutils-0.152-4.9.17")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libasm1-0.152-4.9.17")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libdw1-0.152-4.9.17")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libdw1-32bit-0.152-4.9.17")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libebl1-0.152-4.9.17")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libebl1-32bit-0.152-4.9.17")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libelf1-0.152-4.9.17")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libelf1-32bit-0.152-4.9.17")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"elfutils-0.152-4.9.17")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libasm1-0.152-4.9.17")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libdw1-0.152-4.9.17")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libebl1-0.152-4.9.17")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libelf1-0.152-4.9.17")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libasm1-32bit-0.152-4.9.17")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libdw1-32bit-0.152-4.9.17")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libebl1-32bit-0.152-4.9.17")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libelf1-32bit-0.152-4.9.17")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libasm1-32bit-0.152-4.9.17")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libdw1-32bit-0.152-4.9.17")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libebl1-32bit-0.152-4.9.17")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libelf1-32bit-0.152-4.9.17")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
