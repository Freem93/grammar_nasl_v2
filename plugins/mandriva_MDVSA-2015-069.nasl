#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:069. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(82322);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/08/02 13:41:58 $");

  script_cve_id("CVE-2014-5352", "CVE-2014-5355", "CVE-2014-9421", "CVE-2014-9422", "CVE-2014-9423");
  script_xref(name:"MDVSA", value:"2015:069");

  script_name(english:"Mandriva Linux Security Advisory : krb5 (MDVSA-2015:069)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities has been discovered and corrected in krb5 :

The krb5_gss_process_context_token function in
lib/gssapi/krb5/process_context_token.c in the libgssapi_krb5 library
in MIT Kerberos 5 (aka krb5) through 1.11.5, 1.12.x through 1.12.2,
and 1.13.x before 1.13.1 does not properly maintain security-context
handles, which allows remote authenticated users to cause a denial of
service (use-after-free and double free, and daemon crash) or possibly
execute arbitrary code via crafted GSSAPI traffic, as demonstrated by
traffic to kadmind (CVE-2014-5352).

MIT Kerberos 5 (aka krb5) through 1.13.1 incorrectly expects that a
krb5_read_message data field is represented as a string ending with a
'\0' character, which allows remote attackers to (1) cause a denial of
service (NULL pointer dereference) via a zero-byte version string or
(2) cause a denial of service (out-of-bounds read) by omitting the
'\0' character, related to appl/user_user/server.c and
lib/krb5/krb/recvauth.c (CVE-2014-5355).

The auth_gssapi_unwrap_data function in lib/rpc/auth_gssapi_misc.c in
MIT Kerberos 5 (aka krb5) through 1.11.5, 1.12.x through 1.12.2, and
1.13.x before 1.13.1 does not properly handle partial XDR
deserialization, which allows remote authenticated users to cause a
denial of service (use-after-free and double free, and daemon crash)
or possibly execute arbitrary code via malformed XDR data, as
demonstrated by data sent to kadmind (CVE-2014-9421).

The check_rpcsec_auth function in kadmin/server/kadm_rpc_svc.c in
kadmind in MIT Kerberos 5 (aka krb5) through 1.11.5, 1.12.x through
1.12.2, and 1.13.x before 1.13.1 allows remote authenticated users to
bypass a kadmin/* authorization check and obtain administrative access
by leveraging access to a two-component principal with an initial
kadmind substring, as demonstrated by a ka/x principal
(CVE-2014-9422).

The svcauth_gss_accept_sec_context function in lib/rpc/svc_auth_gss.c
in MIT Kerberos 5 (aka krb5) 1.11.x through 1.11.5, 1.12.x through
1.12.2, and 1.13.x before 1.13.1 transmits uninitialized interposer
data to clients, which allows remote attackers to obtain sensitive
information from process heap memory by sniffing the network for data
in a handle field (CVE-2014-9423).

The updated packages provides a solution for these security issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krb5-pkinit-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64krb53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64krb53-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"krb5-1.9.2-3.9.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"krb5-pkinit-openssl-1.9.2-3.9.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"krb5-server-1.9.2-3.9.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"krb5-server-ldap-1.9.2-3.9.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"krb5-workstation-1.9.2-3.9.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64krb53-1.9.2-3.9.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64krb53-devel-1.9.2-3.9.mbs1")) flag++;

if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"krb5-1.12.2-5.2.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"krb5-pkinit-openssl-1.12.2-5.2.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"krb5-server-1.12.2-5.2.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"krb5-server-ldap-1.12.2-5.2.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"krb5-workstation-1.12.2-5.2.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64krb53-1.12.2-5.2.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64krb53-devel-1.12.2-5.2.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
