#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:246. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(50849);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/06/01 00:15:51 $");

  script_cve_id("CVE-2010-1323", "CVE-2010-1324", "CVE-2010-4020", "CVE-2010-4021");
  script_bugtraq_id(45116, 45117, 45118, 45122);
  script_xref(name:"MDVSA", value:"2010:246");

  script_name(english:"Mandriva Linux Security Advisory : krb5 (MDVSA-2010:246)");
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
"Multiple vulnerabilities were discovered and corrected in krb5 :

An unauthenticated remote attacker could alter a SAM-2 challenge,
affecting the prompt text seen by the user or the kind of response
sent to the KDC. Under some circumstances, this can negate the
incremental security benefit of using a single-use authentication
mechanism token. An unauthenticated remote attacker has a 1/256 chance
of forging KRB-SAFE messages in an application protocol if the
targeted pre-existing session uses an RC4 session key. Few application
protocols use KRB-SAFE messages (CVE-2010-1323).

An unauthenticated remote attacker can forge GSS tokens that are
intended to be integrity-protected but unencrypted, if the targeted
pre-existing application session uses a DES session key. An
authenticated remote attacker can forge PACs if using a KDC that does
not filter client-provided PAC data. This can result in privilege
escalation against a service that relies on PAC contents to make
authorization decisions. An unauthenticated remote attacker has a
1/256 chance of swapping a client-issued KrbFastReq into a different
KDC-REQ, if the armor key is RC4. The consequences are believed to be
minor (CVE-2010-1324).

An authenticated remote attacker that controls a legitimate service
principal has a 1/256 chance of forging the AD-SIGNEDPATH signature if
the TGT key is RC4, allowing it to use self-generated evidence tickets
for S4U2Proxy, instead of tickets obtained from the user or with
S4U2Self. Configurations using RC4 for the TGT key are believed to be
rare. An authenticated remote attacker has a 1/256 chance of forging
AD-KDC-ISSUED signatures on authdata elements in tickets having an RC4
service key, resulting in privilege escalation against a service that
relies on these signatures. There are no known uses of the KDC-ISSUED
authdata container at this time (CVE-2010-4020.

An authenticated remote attacker that controls a legitimate service
principal could obtain a valid service ticket to itself containing
valid KDC-generated authorization data for a client whose TGS-REQ it
has intercepted. The attacker could then use this ticket for S4U2Proxy
to impersonate the targeted client even if the client never
authenticated to the subverted service. The vulnerable configuration
is believed to be rare (CVE-2010-4021).

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2010-007.txt"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krb5-pkinit-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64krb53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64krb53-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkrb53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkrb53-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2010.1", reference:"krb5-1.8.1-5.2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"krb5-pkinit-openssl-1.8.1-5.2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"krb5-server-1.8.1-5.2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"krb5-server-ldap-1.8.1-5.2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"krb5-workstation-1.8.1-5.2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64krb53-1.8.1-5.2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64krb53-devel-1.8.1-5.2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libkrb53-1.8.1-5.2mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libkrb53-devel-1.8.1-5.2mdv2010.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
