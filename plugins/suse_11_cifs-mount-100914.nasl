#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(50895);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/10/25 23:41:52 $");

  script_cve_id("CVE-2010-3069");

  script_name(english:"SuSE 11 / 11.1 Security Update : Samba (SAT Patch Numbers 3099 / 3100)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow in the sid_parse() function of samba could
potentially be exploited by remote attackers to execute arbitrary
code. (CVE-2010-3069)

Additionally the update also contains fixes for the following
non-security issues :

  - Failed to join ADS Domain. (bnc#567013)

  - Samba 3.0 / 3.2 doesn't work with Windows 2008 R2
    (NTLMv2). (bnc#592198)

  - SAMBA - Problem using NTLM authentication with 2008R2.
    (bnc#599873)

  - winbindd crashes in rpcclisettimeout. (bnc#613459)

  - new printers are not seen in samba with registry.
    (bnc#617153)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=567013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=573246"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=583535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=592198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=599873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=613459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=617153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=630812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=632055"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=632852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=637218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3069.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 3099 / 3100 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"cifs-mount-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"libsmbclient0-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"libtalloc1-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"libtdb1-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"libwbclient0-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"samba-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"samba-client-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"samba-krb-printing-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"samba-vscan-0.3.6b-11.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"samba-winbind-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"cifs-mount-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libsmbclient0-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libsmbclient0-32bit-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libtalloc1-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libtalloc1-32bit-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libtdb1-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libtdb1-32bit-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libwbclient0-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libwbclient0-32bit-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"samba-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"samba-32bit-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"samba-client-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"samba-client-32bit-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"samba-krb-printing-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"samba-vscan-0.3.6b-11.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"samba-winbind-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"samba-winbind-32bit-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"cifs-mount-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libsmbclient0-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libtalloc1-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libtdb1-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libwbclient0-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"samba-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"samba-client-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"samba-krb-printing-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"samba-winbind-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"cifs-mount-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libsmbclient0-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libsmbclient0-32bit-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libtalloc1-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libtalloc1-32bit-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libtdb1-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libtdb1-32bit-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libwbclient0-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libwbclient0-32bit-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"samba-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"samba-32bit-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"samba-client-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"samba-client-32bit-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"samba-krb-printing-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"samba-winbind-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"samba-winbind-32bit-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"cifs-mount-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"ldapsmb-1.34b-11.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"libsmbclient0-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"libtalloc1-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"libtdb1-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"libwbclient0-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"samba-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"samba-client-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"samba-krb-printing-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"samba-winbind-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"libsmbclient0-32bit-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"libtalloc1-32bit-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"libtdb1-32bit-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"libwbclient0-32bit-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"samba-32bit-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"samba-client-32bit-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"samba-winbind-32bit-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"libsmbclient0-32bit-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"libtalloc1-32bit-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"libtdb1-32bit-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"libwbclient0-32bit-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"samba-32bit-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"samba-client-32bit-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"samba-winbind-32bit-3.2.7-11.21.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"cifs-mount-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"ldapsmb-1.34b-11.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"libsmbclient0-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"libtalloc1-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"libtdb1-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"libwbclient0-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"samba-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"samba-client-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"samba-krb-printing-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"samba-winbind-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"libsmbclient0-32bit-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"libtalloc1-32bit-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"libtdb1-32bit-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"libwbclient0-32bit-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"samba-32bit-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"samba-client-32bit-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"samba-winbind-32bit-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"libsmbclient0-32bit-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"libtalloc1-32bit-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"libtdb1-32bit-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"libwbclient0-32bit-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"samba-32bit-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"samba-client-32bit-3.4.3-1.19.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"samba-winbind-32bit-3.4.3-1.19.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
