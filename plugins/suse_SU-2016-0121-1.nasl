#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0121-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(87964);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/05/02 15:19:32 $");

  script_cve_id("CVE-2015-4792", "CVE-2015-4802", "CVE-2015-4807", "CVE-2015-4815", "CVE-2015-4816", "CVE-2015-4819", "CVE-2015-4826", "CVE-2015-4830", "CVE-2015-4836", "CVE-2015-4858", "CVE-2015-4861", "CVE-2015-4870", "CVE-2015-4879", "CVE-2015-4895", "CVE-2015-4913");
  script_osvdb_id(129164, 129165, 129167, 129171, 129173, 129174, 129176, 129177, 129179, 129180, 129181, 129182, 129186, 129189, 129190, 130156, 130157, 130158, 130159, 130160, 130161, 130162, 130163, 130164, 130165, 130166);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : mariadb (SUSE-SU-2016:0121-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MariaDB has been updated to version 10.0.22, which brings fixes for
many security issues and other improvements.

The following CVEs have been fixed :

  - 10.0.22: CVE-2015-4802, CVE-2015-4807, CVE-2015-4815,
    CVE-2015-4826, CVE-2015-4830, CVE-2015-4836,
    CVE-2015-4858, CVE-2015-4861, CVE-2015-4870,
    CVE-2015-4913, CVE-2015-4792

  - 10.0.21: CVE-2015-4816, CVE-2015-4819, CVE-2015-4879,
    CVE-2015-4895

The following non-security issues have been fixed :

  - Fix rc.mysql-multi script to properly start instances
    after restart. (bsc#934401)

  - Fix rc.mysql-multi script to restart after crash.
    (bsc#937258)

For a comprehensive list of changes refer to the upstream Release
Notes and Change Log documents :

- https://kb.askmonty.org/en/mariadb-10022-release-notes/

- https://kb.askmonty.org/en/mariadb-10021-release-notes/

- https://kb.askmonty.org/en/mariadb-10022-changelog/

- https://kb.askmonty.org/en/mariadb-10021-changelog/

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/934401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958790"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.askmonty.org/en/mariadb-10021-changelog/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.askmonty.org/en/mariadb-10021-release-notes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.askmonty.org/en/mariadb-10022-changelog/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.askmonty.org/en/mariadb-10022-release-notes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4792.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4802.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4807.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4815.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4816.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4819.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4826.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4830.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4836.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4858.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4861.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4870.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4879.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4895.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4913.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160121-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0bdf1b6e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12 :

zypper in -t patch SUSE-SLE-WE-12-2016-87=1

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2016-87=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2016-87=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2016-87=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqlclient18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqlclient18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqlclient_r18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-errormessages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/18");
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
if (rpm_check(release:"SLES12", sp:"0", reference:"libmysqlclient18-10.0.22-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmysqlclient18-debuginfo-10.0.22-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-10.0.22-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-client-10.0.22-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-client-debuginfo-10.0.22-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-debuginfo-10.0.22-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-debugsource-10.0.22-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-errormessages-10.0.22-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-tools-10.0.22-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mariadb-tools-debuginfo-10.0.22-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmysqlclient18-32bit-10.0.22-20.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libmysqlclient18-debuginfo-32bit-10.0.22-20.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmysqlclient18-10.0.22-20.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmysqlclient18-32bit-10.0.22-20.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmysqlclient18-debuginfo-10.0.22-20.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmysqlclient18-debuginfo-32bit-10.0.22-20.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmysqlclient_r18-10.0.22-20.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmysqlclient_r18-32bit-10.0.22-20.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mariadb-10.0.22-20.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mariadb-client-10.0.22-20.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mariadb-client-debuginfo-10.0.22-20.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mariadb-debuginfo-10.0.22-20.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mariadb-debugsource-10.0.22-20.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"mariadb-errormessages-10.0.22-20.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb");
}