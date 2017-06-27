#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0994-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(90506);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/27 20:24:08 $");

  script_cve_id("CVE-2016-3119");
  script_osvdb_id(136224);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : krb5 (SUSE-SU-2016:0994-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for krb5 fixes the following security issue :

  - CVE-2016-3119: An authenticated attacker with permission
    to modify a principal entry could have caused kadmind to
    dereference a NULL pointer by supplying an empty DB
    argument to the modify_principal command, if kadmind is
    configured to use the LDAP KDB module. (bsc#971942)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971942"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3119.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160994-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ac1491a5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP1 :

zypper in -t patch SUSE-SLE-SDK-12-SP1-2016-586=1

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2016-586=1

SUSE Linux Enterprise Server 12-SP1 :

zypper in -t patch SUSE-SLE-SERVER-12-SP1-2016-586=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2016-586=1

SUSE Linux Enterprise Desktop 12-SP1 :

zypper in -t patch SUSE-SLE-DESKTOP-12-SP1-2016-586=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2016-586=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/13");
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
if (os_ver == "SLES12" && (! ereg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"krb5-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"krb5-client-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"krb5-client-debuginfo-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"krb5-debuginfo-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"krb5-debugsource-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"krb5-doc-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"krb5-plugin-kdb-ldap-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"krb5-plugin-kdb-ldap-debuginfo-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"krb5-plugin-preauth-otp-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"krb5-plugin-preauth-otp-debuginfo-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"krb5-plugin-preauth-pkinit-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"krb5-plugin-preauth-pkinit-debuginfo-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"krb5-server-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"krb5-server-debuginfo-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"krb5-32bit-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"krb5-debuginfo-32bit-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-client-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-client-debuginfo-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-debuginfo-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-debugsource-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-doc-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-plugin-kdb-ldap-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-plugin-kdb-ldap-debuginfo-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-plugin-preauth-otp-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-plugin-preauth-otp-debuginfo-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-plugin-preauth-pkinit-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-plugin-preauth-pkinit-debuginfo-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-server-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-server-debuginfo-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-32bit-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"krb5-debuginfo-32bit-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"krb5-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"krb5-32bit-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"krb5-client-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"krb5-client-debuginfo-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"krb5-debuginfo-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"krb5-debuginfo-32bit-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"krb5-debugsource-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"krb5-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"krb5-32bit-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"krb5-client-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"krb5-client-debuginfo-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"krb5-debuginfo-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"krb5-debuginfo-32bit-1.12.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"krb5-debugsource-1.12.1-28.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5");
}
