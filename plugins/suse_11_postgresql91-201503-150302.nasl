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
  script_id(82470);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/05/31 04:37:06 $");

  script_cve_id("CVE-2014-8161", "CVE-2015-0241", "CVE-2015-0242", "CVE-2015-0243", "CVE-2015-0244");

  script_name(english:"SuSE 11.3 Security Update : postgresql91 (SAT Patch Number 10389)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The PostgreSQL database server was updated to 9.1.15, fixing bugs and
security issues :

  - Fix buffer overruns in to_char(). (CVE-2015-0241)

  - Fix buffer overrun in replacement *printf() functions.
    (CVE-2015-0242)

  - Fix buffer overruns in contrib/pgcrypto. (CVE-2015-0243)

  - Fix possible loss of frontend/backend protocol
    synchronization after an error. (CVE-2015-0244)

  - Fix information leak via constraint-violation error
    messages (CVE-2014-8161). For a comprehensive list of
    fixes, please refer to the following release notes :

  -
    http://www.postgresql.org/docs/9.1/static/release-9-1-15
    .html

  -
    http://www.postgresql.org/docs/9.1/static/release-9-1-14
    .html

  -
    http://www.postgresql.org/docs/9.1/static/release-9-1-13
    .html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=916953"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8161.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0241.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0242.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0243.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0244.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 10389.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpq5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:postgresql91");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:postgresql91-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:postgresql91-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:postgresql91-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/31");
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
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libecpg6-9.1.15-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libpq5-9.1.15-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"postgresql91-9.1.15-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"postgresql91-docs-9.1.15-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libecpg6-9.1.15-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libpq5-9.1.15-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libpq5-32bit-9.1.15-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"postgresql91-9.1.15-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"postgresql91-docs-9.1.15-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libecpg6-9.1.15-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libpq5-9.1.15-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"postgresql91-9.1.15-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"postgresql91-contrib-9.1.15-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"postgresql91-docs-9.1.15-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"postgresql91-server-9.1.15-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libpq5-32bit-9.1.15-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libpq5-32bit-9.1.15-0.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
