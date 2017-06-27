#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2156-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93309);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2016-1234", "CVE-2016-3075", "CVE-2016-3706", "CVE-2016-4429");
  script_osvdb_id(98836, 135497, 137999, 138786);

  script_name(english:"SUSE SLES11 Security Update : glibc (SUSE-SU-2016:2156-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for glibc fixes the following issues :

  - Drop old fix that could break services that start before
    IPv6 is up. (bsc#931399)

  - Do not copy d_name field of struct dirent.
    (CVE-2016-1234, bsc#969727)

  - Fix memory leak in _nss_dns_gethostbyname4_r.
    (bsc#973010)

  - Relocate DSOs in dependency order, fixing a potential
    crash during symbol relocation phase. (bsc#986302)

  - Fix nscd assertion failure in gc. (bsc#965699)

  - Fix stack overflow in _nss_dns_getnetbyname_r.
    (CVE-2016-3075, bsc#973164)

  - Fix getaddrinfo stack overflow in hostent conversion.
    (CVE-2016-3706, bsc#980483)

  - Do not use alloca in clntudp_call. (CVE-2016-4429,
    bsc#980854)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980854"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986302"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1234.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3075.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3706.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4429.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162156-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64884c5c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-glibc-12712=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-glibc-12712=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-glibc-12712=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-i18ndata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/02");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"glibc-32bit-2.11.3-17.102.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"glibc-devel-32bit-2.11.3-17.102.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"glibc-locale-32bit-2.11.3-17.102.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"glibc-profile-32bit-2.11.3-17.102.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"glibc-32bit-2.11.3-17.102.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"glibc-devel-32bit-2.11.3-17.102.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"glibc-locale-32bit-2.11.3-17.102.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"glibc-profile-32bit-2.11.3-17.102.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"glibc-2.11.3-17.102.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"glibc-devel-2.11.3-17.102.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"glibc-html-2.11.3-17.102.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"glibc-i18ndata-2.11.3-17.102.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"glibc-info-2.11.3-17.102.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"glibc-locale-2.11.3-17.102.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"glibc-profile-2.11.3-17.102.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"nscd-2.11.3-17.102.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc");
}
