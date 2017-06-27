#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1264-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(84896);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/05/11 13:40:22 $");

  script_cve_id("CVE-2015-3165", "CVE-2015-3166", "CVE-2015-3167");
  script_bugtraq_id(74787, 74789, 74790);
  script_osvdb_id(122456, 122457, 122458);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : postgresql93 (SUSE-SU-2015:1264-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"PostgreSQL was updated to the security and bugfix release 9.3.8
including 9.3.7.

Security issues fixed :

  - CVE-2015-3165, bsc#931972: Avoid possible crash when
    client disconnects just before the authentication
    timeout expires.

  - CVE-2015-3166, bsc#931973: Consistently check for
    failure of the printf() family of functions.

  - CVE-2015-3167, bsc#931974: In contrib/pgcrypto,
    uniformly report decryption failures as 'Wrong key or
    corrupt data'

Bugs fixed :

  - Protect against wraparound of multixact member IDs.

  - Avoid failures while fsync'ing data directory during
    crash restart.

  - Fix pg_get_functiondef() to show functions' LEAKPROOF
    property, if set.

  - Allow libpq to use TLS protocol versions beyond v1.

  - For the full release notes, see the following two URLs
    http://www.postgresql.org/docs/9.3/static/release-9-3-8.
    html
    http://www.postgresql.org/docs/9.3/static/release-9-3-7.
    html

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/9.3/static/release-9-3-7.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/9.3/static/release-9-3-8.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3165.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3166.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3167.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151264-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bc9dab58"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-328=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-328=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-328=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libecpg6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpq5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql93");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql93-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql93-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql93-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql93-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql93-libs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql93-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql93-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES12", sp:"0", reference:"libecpg6-9.3.8-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libecpg6-debuginfo-9.3.8-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libpq5-9.3.8-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libpq5-debuginfo-9.3.8-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"postgresql93-9.3.8-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"postgresql93-contrib-9.3.8-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"postgresql93-contrib-debuginfo-9.3.8-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"postgresql93-debuginfo-9.3.8-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"postgresql93-debugsource-9.3.8-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"postgresql93-libs-debugsource-9.3.8-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"postgresql93-server-9.3.8-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"postgresql93-server-debuginfo-9.3.8-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libpq5-32bit-9.3.8-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libpq5-debuginfo-32bit-9.3.8-8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libecpg6-9.3.8-8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libecpg6-debuginfo-9.3.8-8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libpq5-32bit-9.3.8-8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libpq5-9.3.8-8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libpq5-debuginfo-32bit-9.3.8-8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libpq5-debuginfo-9.3.8-8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"postgresql93-9.3.8-8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"postgresql93-debuginfo-9.3.8-8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"postgresql93-debugsource-9.3.8-8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"postgresql93-libs-debugsource-9.3.8-8.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql93");
}
