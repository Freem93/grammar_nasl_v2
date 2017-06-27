#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51596);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/10/25 23:41:52 $");

  script_cve_id("CVE-2009-2813", "CVE-2009-2906", "CVE-2009-2948");

  script_name(english:"SuSE 11 Security Update : Samba (SAT Patch Number 1352)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"samba's make_connection_snum() handles certain input incorrectly,
which may lead to disclosure of the root directory. CVE-2009-2813 has
been assigned to this issue. Additionally an information disclosure
vulnerability in mount.cifs has been fixed (CVE-2009-2948) as well as
a DoS condition. (CVE-2009-2906)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=539517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2813.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2906.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2948.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 1352.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:cifs-mount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ldapsmb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libsmbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libtalloc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libtalloc1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libtdb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libtdb1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libwbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:samba-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:samba-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:samba-krb-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:samba-vscan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:samba-winbind-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (pl) audit(AUDIT_OS_NOT, "SuSE 11.0");


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"cifs-mount-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libsmbclient0-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libsmbclient0-32bit-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libtalloc1-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libtalloc1-32bit-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libtdb1-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libtdb1-32bit-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libwbclient0-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libwbclient0-32bit-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"samba-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"samba-32bit-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"samba-client-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"samba-client-32bit-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"samba-krb-printing-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"samba-vscan-0.3.6b-11.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"samba-winbind-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"samba-winbind-32bit-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"cifs-mount-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"ldapsmb-1.34b-11.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"libsmbclient0-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"libsmbclient0-32bit-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"libtalloc1-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"libtalloc1-32bit-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"libtdb1-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"libtdb1-32bit-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"libwbclient0-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"libwbclient0-32bit-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"samba-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"samba-32bit-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"samba-client-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"samba-client-32bit-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"samba-krb-printing-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"samba-winbind-3.2.7-11.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"samba-winbind-32bit-3.2.7-11.8.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
