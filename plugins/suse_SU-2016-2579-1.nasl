#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2579-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(94275);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/10/28 14:05:24 $");

  script_cve_id("CVE-2014-0249");
  script_bugtraq_id(67940);
  script_osvdb_id(107547);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : sssd (SUSE-SU-2016:2579-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for sssd fixes one security issue and three bugs. The
following vulnerability was fixed :

  - CVE-2014-0249: Incorrect expansion of group membership
    when encountering a non-POSIX group. (bsc#880245) The
    following non-security fixes were also included :

  - Prevent crashes of statically linked binaries using
    getpwuid when sssd is used and nscd is turned off or has
    caching disabled. (bsc#993582)

  - Add logrotate configuration to prevent log files from
    growing too large when running with debug mode enabled.
    (bsc#1004220)

  - Order sudo rules by the same logic used by the native
    LDAP support from sudo. (bsc#1002973)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1002973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1004220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/880245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/993582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-0249.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162579-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c21b6e31"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2016-1513=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2016-1513=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2016-1513=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libipa_hbac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libipa_hbac0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_idmap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_sudo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-sssd-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-sssd-config-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-ad-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-ipa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-krb5-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-proxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/26");
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
if (os_ver == "SLES12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"libipa_hbac0-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libipa_hbac0-debuginfo-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsss_idmap0-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsss_idmap0-debuginfo-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsss_sudo-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsss_sudo-debuginfo-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-sssd-config-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-sssd-config-debuginfo-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"sssd-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"sssd-ad-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"sssd-ad-debuginfo-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"sssd-debuginfo-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"sssd-debugsource-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"sssd-ipa-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"sssd-ipa-debuginfo-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"sssd-krb5-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"sssd-krb5-common-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"sssd-krb5-common-debuginfo-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"sssd-krb5-debuginfo-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"sssd-ldap-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"sssd-ldap-debuginfo-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"sssd-proxy-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"sssd-proxy-debuginfo-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"sssd-tools-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"sssd-tools-debuginfo-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"sssd-32bit-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"sssd-debuginfo-32bit-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libipa_hbac0-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libipa_hbac0-debuginfo-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsss_idmap0-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsss_idmap0-debuginfo-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsss_sudo-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsss_sudo-debuginfo-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"python-sssd-config-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"python-sssd-config-debuginfo-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"sssd-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"sssd-32bit-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"sssd-ad-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"sssd-ad-debuginfo-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"sssd-debuginfo-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"sssd-debuginfo-32bit-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"sssd-debugsource-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"sssd-ipa-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"sssd-ipa-debuginfo-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"sssd-krb5-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"sssd-krb5-common-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"sssd-krb5-common-debuginfo-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"sssd-krb5-debuginfo-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"sssd-ldap-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"sssd-ldap-debuginfo-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"sssd-proxy-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"sssd-proxy-debuginfo-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"sssd-tools-1.11.5.1-28.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"sssd-tools-debuginfo-1.11.5.1-28.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sssd");
}
