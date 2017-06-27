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
  script_id(81312);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/05/31 04:37:06 $");

  script_cve_id("CVE-2014-5352", "CVE-2014-9421", "CVE-2014-9422", "CVE-2014-9423");

  script_name(english:"SuSE 11.3 Security Update : krb5 (SAT Patch Number 10282)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"krb5 has been updated to fix four security issues :

  - gss_process_context_token() incorrectly frees context
    (bsc#912002). (CVE-2014-5352)

  - kadmind doubly frees partial deserialization results
    (bsc#912002). (CVE-2014-9421)

  - kadmind incorrectly validates server principal name
    (bsc#912002). (CVE-2014-9422)

  - libgssrpc server applications leak uninitialized bytes
    (bsc#912002) Additionally, these non-security issues
    have been fixed :. (CVE-2014-9423)

  - Winbind process hangs indefinitely without DC.
    (bsc#872912)

  - Hanging winbind processes. (bsc#906557)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=872912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=906557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=912002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-5352.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9421.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9422.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9423.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 10282.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:krb5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:krb5-apps-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:krb5-apps-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:krb5-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:krb5-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:krb5-plugin-kdb-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:krb5-plugin-preauth-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:krb5-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"krb5-1.6.3-133.49.66.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"krb5-client-1.6.3-133.49.66.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"krb5-1.6.3-133.49.66.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"krb5-32bit-1.6.3-133.49.66.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"krb5-client-1.6.3-133.49.66.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"krb5-1.6.3-133.49.66.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"krb5-apps-clients-1.6.3-133.49.66.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"krb5-apps-servers-1.6.3-133.49.66.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"krb5-client-1.6.3-133.49.66.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"krb5-doc-1.6.3-133.49.66.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"krb5-plugin-kdb-ldap-1.6.3-133.49.66.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"krb5-plugin-preauth-pkinit-1.6.3-133.49.66.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"krb5-server-1.6.3-133.49.66.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"krb5-32bit-1.6.3-133.49.66.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"krb5-32bit-1.6.3-133.49.66.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
