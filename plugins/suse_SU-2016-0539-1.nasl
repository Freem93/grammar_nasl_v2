#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0539-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(88891);
  script_version("$Revision: 2.14 $");
  script_cvs_date("$Date: 2016/12/27 20:14:34 $");

  script_cve_id("CVE-2007-4772", "CVE-2016-0766", "CVE-2016-0773");
  script_bugtraq_id(27163);
  script_osvdb_id(40905, 134458, 134459);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : postgresql93 (SUSE-SU-2016:0539-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for postgresql93 fixes the following issues :

  - Security and bugfix release 9.3.11 :

  - Fix infinite loops and buffer-overrun problems in
    regular expressions (CVE-2016-0773, bsc#966436).

  - Fix regular-expression compiler to handle loops of
    constraint arcs (CVE-2007-4772).

  - Prevent certain PL/Java parameters from being set by
    non-superusers (CVE-2016-0766, bsc#966435).

  - Fix many issues in pg_dump with specific object types

  - Prevent over-eager pushdown of HAVING clauses for
    GROUPING SETS

  - Fix deparsing error with ON CONFLICT ... WHERE clauses

  - Fix tableoid errors for postgres_fdw

  - Prevent floating-point exceptions in pgbench

  - Make \det search Foreign Table names consistently

  - Fix quoting of domain constraint names in pg_dump

  - Prevent putting expanded objects into Const nodes

  - Allow compile of PL/Java on Windows

  - Fix 'unresolved symbol' errors in PL/Python execution

  - Allow Python2 and Python3 to be used in the same
    database

  - Add support for Python 3.5 in PL/Python

  - Fix issue with subdirectory creation during initdb

  - Make pg_ctl report status correctly on Windows

  - Suppress confusing error when using pg_receivexlog with
    older servers

  - Multiple documentation corrections and additions

  - Fix erroneous hash calculations in
    gin_extract_jsonb_path()

  - For the full release notse, see:
    http://www.postgresql.org/docs/9.3/static/release-9-3-11
    .html

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/9.3/static/release-9-3-11.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2007-4772.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0766.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0773.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160539-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d29b66d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2016-292=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2016-292=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2016-292=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql93");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql93-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql93-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql93-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql93-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql93-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql93-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"postgresql93-9.3.11-14.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"postgresql93-contrib-9.3.11-14.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"postgresql93-contrib-debuginfo-9.3.11-14.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"postgresql93-debuginfo-9.3.11-14.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"postgresql93-debugsource-9.3.11-14.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"postgresql93-server-9.3.11-14.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"postgresql93-server-debuginfo-9.3.11-14.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"postgresql93-9.3.11-14.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"postgresql93-debuginfo-9.3.11-14.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"postgresql93-debugsource-9.3.11-14.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql93");
}
