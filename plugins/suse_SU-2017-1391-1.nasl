#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:1391-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(100404);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/25 13:29:27 $");

  script_cve_id("CVE-2017-7494");

  script_name(english:"SUSE SLES11 Security Update : samba (SUSE-SU-2017:1391-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for samba fixes the following issue :

  - An unprivileged user with access to the samba server
    could cause smbd to load a specially crafted shared
    library, which then had the ability to execute arbitrary
    code on the server as 'root'. [CVE-2017-7494, bso#12780,
    bsc#1038231]

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1038231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7494.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20171391-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?41b8bec1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-samba-13127=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-samba-13127=1

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-samba-13127=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-samba-13127=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-samba-13127=1

SUSE Linux Enterprise Debuginfo 11-SP3:zypper in -t patch
dbgsp3-samba-13127=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/25");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libsmbclient0-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libtalloc2-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libtdb1-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libtevent0-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libwbclient0-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"samba-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"samba-client-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"samba-winbind-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libsmbclient0-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libtalloc2-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libtdb1-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libtevent0-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libwbclient0-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"samba-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"samba-client-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"samba-winbind-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"ldapsmb-1.34b-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libldb1-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libsmbclient0-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libtalloc2-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libtdb1-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libtevent0-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libwbclient0-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"samba-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"samba-client-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"samba-krb-printing-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"samba-winbind-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libsmbclient0-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libtalloc2-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libtdb1-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libtevent0-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libwbclient0-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"samba-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"samba-client-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"samba-winbind-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libsmbclient0-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libtalloc2-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libtdb1-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libtevent0-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libwbclient0-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"samba-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"samba-client-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"samba-winbind-32bit-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"ldapsmb-1.34b-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libldb1-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libsmbclient0-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libtalloc2-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libtdb1-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libtevent0-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libwbclient0-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"samba-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"samba-client-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"samba-krb-printing-3.6.3-93.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"samba-winbind-3.6.3-93.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
