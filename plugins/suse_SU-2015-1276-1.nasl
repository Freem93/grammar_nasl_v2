#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1276-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(84914);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/08/01 15:11:53 $");

  script_cve_id("CVE-2014-5353", "CVE-2014-5354", "CVE-2014-5355", "CVE-2015-2694");
  script_bugtraq_id(71679, 71680, 74042, 74824);
  script_osvdb_id(115960, 115961, 118567, 118568, 118569, 118570, 121429);

  script_name(english:"SUSE SLES12 Security Update : krb5 (SUSE-SU-2015:1276-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"krb5 was updated to fix four security issues.

These security issues were fixed :

  - CVE-2014-5353: NULL pointer dereference when using a
    ticket policy name as password name (bsc#910457).

  - CVE-2014-5354: NULL pointer dereference when using
    keyless entries (bsc#910458).

  - CVE-2014-5355: Denial of service in krb5_read_message
    (bsc#918595).

  - CVE-2015-2694: OTP and PKINIT kdcpreauth modules leading
    to requires_preauth bypass (bsc#928978).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/910457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/910458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/918595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/928978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-5353.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-5354.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-5355.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2694.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151276-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e834cd3a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-335=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-335=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-plugin-kdb-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-plugin-kdb-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-plugin-preauth-otp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-plugin-preauth-otp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-plugin-preauth-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-plugin-preauth-pkinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/22");
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
if (! ereg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-1.12.1-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-client-1.12.1-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-client-debuginfo-1.12.1-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-debuginfo-1.12.1-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-debugsource-1.12.1-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-doc-1.12.1-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-plugin-kdb-ldap-1.12.1-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-plugin-kdb-ldap-debuginfo-1.12.1-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-plugin-preauth-otp-1.12.1-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-plugin-preauth-otp-debuginfo-1.12.1-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-plugin-preauth-pkinit-1.12.1-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-plugin-preauth-pkinit-debuginfo-1.12.1-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-server-1.12.1-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-server-debuginfo-1.12.1-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-32bit-1.12.1-16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-debuginfo-32bit-1.12.1-16.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5");
}
