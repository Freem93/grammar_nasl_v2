#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2003:043. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14027);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/31 23:47:34 $");

  script_cve_id("CVE-2002-0036", "CVE-2003-0028", "CVE-2003-0058", "CVE-2003-0059", "CVE-2003-0072", "CVE-2003-0082", "CVE-2003-0138", "CVE-2003-0139");
  script_xref(name:"MDKSA", value:"2003:043-1");

  script_name(english:"Mandrake Linux Security Advisory : krb5 (MDKSA-2003:043-1)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandrake Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilties have been found in the Kerberos network
authentication system. The MIT Kerberos team have released an advisory
detailing these vulnerabilties, a description of which follows.

An integer signedness error in the ASN.1 decoder before version 1.2.5
allows remote attackers to cause a crash of the server via a large
unsigned data element length, which is later used as a negative value
(CVE-2002-0036). Mandrake Linux 9.0+ is not affected by this problem.

Vulnerabilties have been found in the RPC library used by the kadmin
service. A faulty length check in the RPC library exposes kadmind to
an integer overflow which can be used to crash kadmind
(CVE-2003-0028).

The KDC (Key Distribution Center) before version 1.2.5 allows remote,
authenticated attackers to cause a crash on KDCs within the same realm
using a certain protocol that causes a null dereference
(CVE-2003-0058). Mandrake Linux 9.0+ is not affected by this problem.

Users from one realm can impersonate users in other realms that have
the same inter-realm keys due to a vulnerability in Kerberos 1.2.3 and
earlier (CVE-2003-0059). Mandrake Linux 9.0+ is not affected by this
problem.

The KDC allows remote, authenticated users to cause a crash on KDCs
within the same realm using a certain protocol request that causes an
out-of-bounds read of an array (CVE-2003-0072).

The KDC allows remote, authenticated users to cause a crash on KDCs
within the same realm using a certain protocol request that causes the
KDC to corrupt its heap (CVE-2003-0082).

Vulnerabilities have been discovered in the Kerberos IV authentication
protocol which allow an attacker with knowledge of a cross-realm key,
which is shared in another realm, to impersonate a principle in that
realm to any service in that realm. This vulnerability can only be
closed by disabling cross-realm authentication in Kerberos IV
(CVE-2003-0138).

Vulnerabilities have been discovered in the support for triple-DES
keys in the Kerberos IV authentication protocol which is included in
MIT Kerberos (CVE-2003-0139).

MandrakeSoft encourages all users to upgrade to these updated packages
immediately which contain patches to correct all of the previously
noted vulnerabilities. These packages also disable Kerberos IV
cross-realm authentication by default.

Update :

The packages for Mandrake Linux 9.1 and 9.1/PPC were not GPG-signed.
This has been fixed and as a result the md5sums have changed. Thanks
to Mark Lyda for pointing this out."
  );
  # http://web.mit.edu/kerberos/www/advisories/MITKRB5-SA-2003-001-multiple.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4ced782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://web.mit.edu/kerberos/www/advisories/MITKRB5-SA-2003-003-xdr.txt"
  );
  # http://web.mit.edu/kerberos/www/advisories/MITKRB5-SA-2003-004-krb4.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?49b852e4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://web.mit.edu/kerberos/www/advisories/MITKRB5-SA-2003-005-buf.txt"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ftp-client-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ftp-server-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:telnet-client-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:telnet-server-krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"ftp-client-krb5-1.2.7-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"ftp-server-krb5-1.2.7-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"krb5-devel-1.2.7-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"krb5-libs-1.2.7-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"krb5-server-1.2.7-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"krb5-workstation-1.2.7-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"telnet-client-krb5-1.2.7-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"telnet-server-krb5-1.2.7-1.1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
