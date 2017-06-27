#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2418-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93808);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2017/05/19 14:17:02 $");

  script_cve_id("CVE-2016-5423", "CVE-2016-5424");
  script_osvdb_id(142811, 142826);

  script_name(english:"SUSE SLES11 Security Update : postgresql94 (SUSE-SU-2016:2418-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for postgresql94 to version 9.4.9 fixes the several
issues. These security issues were fixed :

  - CVE-2016-5423: CASE/WHEN with inlining can cause
    untrusted pointer dereference (bsc#993454).

  - CVE-2016-5424: Fix client programs' handling of special
    characters in database and role names (bsc#993453). For
    the non-security issues please refer to

- http://www.postgresql.org/docs/9.4/static/release-9-4-9.html

- http://www.postgresql.org/docs/9.4/static/release-9-4-8.html

- http://www.postgresql.org/docs/9.4/static/release-9-4-7.html

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/9.4/static/release-9-4-7.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/9.4/static/release-9-4-8.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/9.4/static/release-9-4-9.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/993453"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/993454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5423.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5424.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162418-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e45a496"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Manager 2.1:zypper in -t patch sleman21-postgresql94-12766=1

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-postgresql94-12766=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-postgresql94-12766=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-postgresql94-12766=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql94");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql94-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql94-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql94-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libpq5-32bit-9.4.9-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libpq5-32bit-9.4.9-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libecpg6-9.4.9-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libpq5-9.4.9-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"postgresql94-9.4.9-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"postgresql94-contrib-9.4.9-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"postgresql94-docs-9.4.9-0.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"postgresql94-server-9.4.9-0.19.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql94");
}
