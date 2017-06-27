#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0290-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83682);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/05/11 13:40:21 $");

  script_cve_id("CVE-2014-5351", "CVE-2014-5352", "CVE-2014-9421", "CVE-2014-9422", "CVE-2014-9423");
  script_bugtraq_id(70380, 72494, 72495, 72496, 72503);
  script_osvdb_id(111907, 117920, 117921, 117922, 117923);

  script_name(english:"SUSE SLES12 Security Update : krb5 (SUSE-SU-2015:0290-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MIT kerberos krb5 was updated to fix several security issues and bugs.

Security issues fixed: CVE-2014-5351: The kadm5_randkey_principal_3
function in lib/kadm5/srv/svr_principal.c in kadmind in MIT Kerberos 5
(aka krb5) sent old keys in a response to a -randkey -keepold request,
which allowed remote authenticated users to forge tickets by
leveraging administrative access.

  - CVE-2014-5352: In the MIT krb5 libgssapi_krb5 library,
    after gss_process_context_token() is used to process a
    valid context deletion token, the caller was left with a
    security context handle containing a dangling pointer.
    Further uses of this handle would have resulted in
    use-after-free and double-free memory access violations.
    libgssrpc server applications such as kadmind were
    vulnerable as they can be instructed to call
    gss_process_context_token().

  - CVE-2014-9421: If the MIT krb5 kadmind daemon receives
    invalid XDR data from an authenticated user, it may have
    performed use-after-free and double-free memory access
    violations while cleaning up the partial deserialization
    results. Other libgssrpc server applications might also
    been vulnerable if they contain insufficiently defensive
    XDR functions.

  - CVE-2014-9422: The MIT krb5 kadmind daemon incorrectly
    accepted authentications to two-component server
    principals whose first component is a left substring of
    'kadmin' or whose realm is a left prefix of the default
    realm.

  - CVE-2014-9423: libgssrpc applications including kadmind
    output four or eight bytes of uninitialized memory to
    the network as part of an unused 'handle' field in
    replies to clients.

Bugs fixed :

  - Work around replay cache creation race; (bnc#898439).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-5351.html"
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
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/897874"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/898439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/912002"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150290-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71f24584"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-74=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-74=1

SUSE Linux Enterprise Build System Kit 12 :

zypper in -t patch SUSE-SLE-BSK-12-2015-74=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
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
if (cpu >!< "s390x") audit(AUDIT_ARCH_NOT, "s390x", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"krb5-1.12.1-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"krb5-client-1.12.1-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"krb5-client-debuginfo-1.12.1-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"krb5-debuginfo-1.12.1-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"krb5-debugsource-1.12.1-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"krb5-doc-1.12.1-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"krb5-plugin-kdb-ldap-1.12.1-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"krb5-plugin-kdb-ldap-debuginfo-1.12.1-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"krb5-plugin-preauth-otp-1.12.1-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"krb5-plugin-preauth-otp-debuginfo-1.12.1-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"krb5-plugin-preauth-pkinit-1.12.1-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"krb5-plugin-preauth-pkinit-debuginfo-1.12.1-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"krb5-server-1.12.1-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"krb5-server-debuginfo-1.12.1-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"krb5-32bit-1.12.1-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"krb5-debuginfo-32bit-1.12.1-9.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5");
}
