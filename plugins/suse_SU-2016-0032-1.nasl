#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0032-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(87863);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/27 20:14:34 $");

  script_cve_id("CVE-2015-5252", "CVE-2015-5296", "CVE-2015-5299", "CVE-2015-5330");
  script_osvdb_id(131935, 131936, 131937, 131938);

  script_name(english:"SUSE SLES11 Security Update : samba (SUSE-SU-2016:0032-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for Samba fixes the following security issues :

  - CVE-2015-5330: Remote read memory exploit in LDB
    (bnc#958586).

  - CVE-2015-5252: Insufficient symlink verification (file
    access outside the share) (bnc#958582).

  - CVE-2015-5296: No man in the middle protection when
    forcing smb encryption on the client side (bnc#958584).

  - CVE-2015-5299: Currently the snapshot browsing is not
    secure thru windows previous version (shadow_copy2)
    (bnc#958583).

Non-security issues fixed :

  - Prevent NULL pointer access in samlogon fallback when
    security credentials are null (bnc#949022).

  - Address unrecoverable winbind failure: 'key length too
    large' (bnc#934299).

  - Take resource group sids into account when caching
    netsamlogon data (bnc#912457).

  - Use domain name if search by domain SID fails to send
    SIDHistory lookups to correct idmap backend
    (bnc#773464).

  - Remove deprecated base_rid example from idmap_rid
    manpage (bnc#913304).

  - Purge printer name cache on spoolss SetPrinter change
    (bnc#901813).

  - Fix lookup of groups with 'Local Domain' scope from
    Active Directory (bnc#948244).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/295284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/773464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/901813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/912457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/913304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/934299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/948244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5252.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5296.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5299.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5330.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160032-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?885d3d1b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP2-LTSS :

zypper in -t patch slessp2-samba-12297=1

SUSE Linux Enterprise Debuginfo 11-SP2 :

zypper in -t patch dbgsp2-samba-12297=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ldapsmb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtalloc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtdb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-krb-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/12");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"libsmbclient0-32bit-3.6.3-45.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"libtalloc2-32bit-3.6.3-45.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"libtdb1-32bit-3.6.3-45.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"libtevent0-32bit-3.6.3-45.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"libwbclient0-32bit-3.6.3-45.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"samba-32bit-3.6.3-45.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"samba-client-32bit-3.6.3-45.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"samba-winbind-32bit-3.6.3-45.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"libsmbclient0-32bit-3.6.3-45.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"libtalloc2-32bit-3.6.3-45.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"libtdb1-32bit-3.6.3-45.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"libtevent0-32bit-3.6.3-45.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"libwbclient0-32bit-3.6.3-45.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"samba-32bit-3.6.3-45.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"samba-client-32bit-3.6.3-45.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"samba-winbind-32bit-3.6.3-45.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"ldapsmb-1.34b-45.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"libldb1-3.6.3-45.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"libsmbclient0-3.6.3-45.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"libtalloc2-3.6.3-45.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"libtdb1-3.6.3-45.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"libtevent0-3.6.3-45.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"libwbclient0-3.6.3-45.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"samba-3.6.3-45.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"samba-client-3.6.3-45.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"samba-krb-printing-3.6.3-45.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"samba-winbind-3.6.3-45.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
