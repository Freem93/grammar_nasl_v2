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
  script_id(82021);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/24 13:22:29 $");

  script_cve_id("CVE-2014-9114");

  script_name(english:"SuSE 11.3 Security Update : util-linux (SAT Patch Number 10452)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"util-linux has been updated to fix one security issue :

  - command injection flaw in blkid (bnc#907434).
    Additionally, these non-security issues have been fixed
    :. (CVE-2014-9114)

  - Fix possible script hang. (bnc#888678)

  - Enable build of libmount / findmnt. (bnc#900965)

  - Don't stop trying filesystem when mounting fails with
    EACCESS. (bnc#918041)

  - Fix possible loop in findmnt (bsc#917164)

  - Recognize Unisys s-Par as hypervisor (FATE#318231)

  - Include the utmpdump.1 manpage (bsc#901549)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=888678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=900965"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=901549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=907434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=917164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=918041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9114.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 10452.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libblkid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libblkid1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libuuid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libuuid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libuuid1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:util-linux-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:uuid-runtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/24");
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
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libblkid1-2.19.1-6.62.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libuuid-devel-2.19.1-6.62.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libuuid1-2.19.1-6.62.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"util-linux-2.19.1-6.62.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"util-linux-lang-2.19.1-6.62.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"uuid-runtime-2.19.1-6.62.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libblkid1-2.19.1-6.62.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libblkid1-32bit-2.19.1-6.62.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libuuid-devel-2.19.1-6.62.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libuuid1-2.19.1-6.62.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libuuid1-32bit-2.19.1-6.62.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"util-linux-2.19.1-6.62.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"util-linux-lang-2.19.1-6.62.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"uuid-runtime-2.19.1-6.62.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libblkid1-2.19.1-6.62.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libuuid1-2.19.1-6.62.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"util-linux-2.19.1-6.62.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"util-linux-lang-2.19.1-6.62.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"uuid-runtime-2.19.1-6.62.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libblkid1-32bit-2.19.1-6.62.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libuuid1-32bit-2.19.1-6.62.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libblkid1-32bit-2.19.1-6.62.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libuuid1-32bit-2.19.1-6.62.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
