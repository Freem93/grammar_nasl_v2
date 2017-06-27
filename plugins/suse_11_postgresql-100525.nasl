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
  script_id(50958);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2013/10/25 23:52:02 $");

  script_cve_id("CVE-2010-0733", "CVE-2010-1169", "CVE-2010-1170", "CVE-2010-1975");

  script_name(english:"SuSE 11 / 11.1 Security Update : postgresql (SAT Patch Numbers 2457 / 2458)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of postgresql fixes several minor security 
vulnerabilities :

  - Postgresql does not properly check privileges during
    certain RESET ALL operations, which allows remote
    authenticated users to remove arbitrary parameter
    settings. (CVE-2010-1975)

  - The PL/Tcl implementation in postgresql loads Tcl code
    from the pltcl_modules table regardless of the table's
    ownership and permissions, which allows remote
    authenticated users with database creation privileges to
    execute arbitrary Tcl code. (CVE-2010-1170)

  - Postgresql does not properly restrict PL/perl
    procedures, which allows remote authenticated users with
    database creation privileges to execute arbitrary Perl
    code via a crafted script. (CVE-2010-1169)

  - An integer overflow in postgresql allows remote
    authenticated users to crash the daemon with a SELECT
    statement. (CVE-2010-0733)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=588996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=605845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=605926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=607778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0733.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1169.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1170.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1975.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 2457 / 2458 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:postgresql-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/25");
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


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"postgresql-8.3.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"postgresql-libs-8.3.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"postgresql-8.3.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"postgresql-libs-8.3.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"postgresql-libs-32bit-8.3.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"postgresql-8.3.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"postgresql-libs-8.3.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"postgresql-8.3.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"postgresql-libs-8.3.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"postgresql-libs-32bit-8.3.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"postgresql-8.3.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"postgresql-contrib-8.3.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"postgresql-docs-8.3.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"postgresql-libs-8.3.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"postgresql-server-8.3.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"postgresql-libs-32bit-8.3.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"postgresql-libs-32bit-8.3.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"postgresql-8.3.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"postgresql-contrib-8.3.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"postgresql-docs-8.3.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"postgresql-libs-8.3.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"postgresql-server-8.3.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"postgresql-libs-32bit-8.3.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"postgresql-libs-32bit-8.3.11-0.1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
