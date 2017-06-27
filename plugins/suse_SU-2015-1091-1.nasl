#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1091-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(84338);
  script_version("$Revision: 2.11 $");
  script_cvs_date("$Date: 2016/05/11 13:40:22 $");

  script_cve_id("CVE-2015-3165", "CVE-2015-3166", "CVE-2015-3167");
  script_bugtraq_id(74787, 74789, 74790);
  script_osvdb_id(122456, 122457, 122458);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : postgresql91 (SUSE-SU-2015:1091-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update provides PostgreSQL 9.1.18, which brings fixes for
security issues and other enhancements.

The following vulnerabilities have been fixed :

CVE-2015-3165: Avoid possible crash when client disconnects.
(bsc#931972)

CVE-2015-3166: Consistently check for failure of the *printf().
(bsc#931973)

CVE-2015-3167: In contrib/pgcrypto, uniformly report decryption
failures. (bsc#931974)

For a comprehensive list of changes, please refer to <a
href='http://www.postgresql.org/docs/9.1/static/release-9-1-18.html'>h
ttp://www.postgresql.org/docs/9.1/static/release-9-1-18.html</a>.

This update also includes changes in PostgreSQL's packaging to prepare
for the migration to the new major version 9.4. (FATE#316970,
bsc#907651)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/9.1/static/release-9-1-18.html'"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/9.1/static/release-9-1-18.html</a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/907651"
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
    value:"https://bugzilla.suse.com/932040"
  );
  # https://download.suse.com/patch/finder/?keywords=00fcb88ab431584bc7bf32ba75396dee
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?36f6d275"
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
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151091-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?23fcfb6c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Manager Server :

zypper in -t patch sleman21-postgresql91-201505=10760

SUSE Linux Enterprise Software Development Kit 11 SP3 :

zypper in -t patch sdksp3-postgresql91-201505=10760

SUSE Linux Enterprise Server 11 SP3 for VMware :

zypper in -t patch slessp3-postgresql91-201505=10760

SUSE Linux Enterprise Server 11 SP3 :

zypper in -t patch slessp3-postgresql91-201505=10760

SUSE Linux Enterprise Desktop 11 SP3 :

zypper in -t patch sledsp3-postgresql91-201505=10760

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql91");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql91-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql91-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql91-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/23");
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
if (! ereg(pattern:"^(SLED11|SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11 / SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! ereg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", reference:"postgresql91-9.1.18-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"postgresql91-contrib-9.1.18-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"postgresql91-docs-9.1.18-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"postgresql91-server-9.1.18-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"postgresql91-9.1.18-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"postgresql91-docs-9.1.18-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"postgresql91-9.1.18-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"postgresql91-docs-9.1.18-0.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql91");
}
