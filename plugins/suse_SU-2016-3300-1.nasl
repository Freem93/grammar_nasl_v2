#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:3300-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(96262);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/05/15 14:02:24 $");

  script_cve_id("CVE-2016-2125", "CVE-2016-2126");
  script_osvdb_id(14470, 149001, 149002);

  script_name(english:"SUSE SLES11 Security Update : samba (SUSE-SU-2016:3300-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for samba provides the following fixes: Security issues
fixed :

  - CVE-2016-2125: Don't send delegated credentials to all
    servers. (bsc#1014441)

  - CVE-2016-2126: Prevent denial of service due to a client
    triggered crash in the winbindd parent process.
    (bsc#1014442) Non security issues fixed :

  - Allow SESSION KEY setup without signing. (bsc#1009711)

  - Fix crash bug in tevent_queue_immediate_trigger().
    (bsc#1003731)

  - Don't fail when using default domain with
    user@domain.com format. (bsc#997833)

  - Prevent core, make sure response->extra_data.data is
    always cleared out. (bsc#993692)

  - Honor smb.conf socket options in winbind. (bsc#975131)

  - Fix crash with net rpc join. (bsc#978898)

  - Fix a regression verifying the security trailer.
    (bsc#978898)

  - Fix updating netlogon credentials. (bsc#978898)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1009711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1014441"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1014442"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/993692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/997833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2125.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2126.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20163300-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e1bca7a9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP2-LTSS:zypper in -t patch
slessp2-samba-12925=1

SUSE Linux Enterprise Debuginfo 11-SP2:zypper in -t patch
dbgsp2-samba-12925=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"1999/07/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"libsmbclient0-32bit-3.6.3-56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"libtalloc2-32bit-3.6.3-56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"libtdb1-32bit-3.6.3-56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"libtevent0-32bit-3.6.3-56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"libwbclient0-32bit-3.6.3-56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"samba-32bit-3.6.3-56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"samba-client-32bit-3.6.3-56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"samba-winbind-32bit-3.6.3-56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"libsmbclient0-32bit-3.6.3-56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"libtalloc2-32bit-3.6.3-56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"libtdb1-32bit-3.6.3-56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"libtevent0-32bit-3.6.3-56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"libwbclient0-32bit-3.6.3-56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"samba-32bit-3.6.3-56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"samba-client-32bit-3.6.3-56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"samba-winbind-32bit-3.6.3-56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"ldapsmb-1.34b-56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"libldb1-3.6.3-56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"libsmbclient0-3.6.3-56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"libtalloc2-3.6.3-56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"libtdb1-3.6.3-56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"libtevent0-3.6.3-56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"libwbclient0-3.6.3-56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"samba-3.6.3-56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"samba-client-3.6.3-56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"samba-krb-printing-3.6.3-56.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"samba-winbind-3.6.3-56.1")) flag++;


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
