#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:270. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(70998);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/11/25 11:41:42 $");

  script_cve_id("CVE-2013-1739", "CVE-2013-1741", "CVE-2013-2566", "CVE-2013-5605", "CVE-2013-5606", "CVE-2013-5607");
  script_bugtraq_id(62966, 63737);
  script_xref(name:"MDVSA", value:"2013:270");

  script_name(english:"Mandriva Linux Security Advisory : nss (MDVSA-2013:270)");
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
"Multiple security issues was identified and fixed in mozilla NSPR and
NSS :

Mozilla Network Security Services (NSS) before 3.15.2 does not ensure
that data structures are initialized before read operations, which
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors that trigger a decryption failure
(CVE-2013-1739).

Integer overflow in Mozilla Network Security Services (NSS) 3.15
before 3.15.3 allows remote attackers to cause a denial of service or
possibly have unspecified other impact via a large size value
(CVE-2013-1741).

The RC4 algorithm, as used in the TLS protocol and SSL protocol, has
many single-byte biases, which makes it easier for remote attackers to
conduct plaintext-recovery attacks via statistical analysis of
ciphertext in a large number of sessions that use the same plaintext
(CVE-2013-2566).

Mozilla Network Security Services (NSS) 3.14 before 3.14.5 and 3.15
before 3.15.3 allows remote attackers to cause a denial of service or
possibly have unspecified other impact via invalid handshake packets
(CVE-2013-5605).

The CERT_VerifyCert function in lib/certhigh/certvfy.c in Mozilla
Network Security Services (NSS) 3.15 before 3.15.3 provides an
unexpected return value for an incompatible key-usage certificate when
the CERTVerifyLog argument is valid, which might allow remote
attackers to bypass intended access restrictions via a crafted
certificate (CVE-2013-5606).

Integer overflow in the PL_ArenaAllocate function in Mozilla Netscape
Portable Runtime (NSPR) before 4.10.2, as used in Firefox before
25.0.1, Firefox ESR 17.x before 17.0.11 and 24.x before 24.1.1, and
SeaMonkey before 2.22.1, allows remote attackers to cause a denial of
service (application crash) or possibly have unspecified other impact
via a crafted X.509 certificate, a related issue to CVE-2013-1741
(CVE-2013-5607).

The NSPR packages has been upgraded to the 4.10.2 version and the NSS
packages has been upgraded to the 3.15.3 version which is unaffected
by these security flaws.

Additionally the rootcerts packages has been upgraded with the latest
certdata.txt file as of 2013/11/11 from mozilla."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-103.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.mageia.org/show_bug.cgi?id=11669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://developer.mozilla.org/en-US/docs/NSS/NSS_3.15.3_release_notes"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nspr4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nss-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nss-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rootcerts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rootcerts-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64nspr-devel-4.10.2-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64nspr4-4.10.2-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64nss-devel-3.15.3-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64nss-static-devel-3.15.3-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64nss3-3.15.3-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"nss-3.15.3-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"nss-doc-3.15.3-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"rootcerts-20131111.00-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"rootcerts-java-20131111.00-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
