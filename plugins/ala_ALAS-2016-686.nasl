#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-686.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(90514);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/10/07 15:17:41 $");

  script_cve_id("CVE-2015-5370", "CVE-2016-2110", "CVE-2016-2111", "CVE-2016-2112", "CVE-2016-2113", "CVE-2016-2114", "CVE-2016-2115", "CVE-2016-2118");
  script_xref(name:"ALAS", value:"2016-686");

  script_name(english:"Amazon Linux AMI : samba (ALAS-2016-686) (Badlock)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple flaws were found in Samba's DCE/RPC protocol implementation.
A remote, authenticated attacker could use these flaws to cause a
denial of service against the Samba server (high CPU load or a crash)
or, possibly, execute arbitrary code with the permissions of the user
running Samba (root). This flaw could also be used to downgrade a
secure DCE/RPC connection by a man-in-the-middle attacker taking
control of an Active Directory (AD) object and compromising the
security of a Samba Active Directory Domain Controller (DC).
(CVE-2015-5370)

A protocol flaw, publicly referred to as Badlock, was found in the
Security Account Manager Remote Protocol (MS-SAMR) and the Local
Security Authority (Domain Policy) Remote Protocol (MS-LSAD). Any
authenticated DCE/RPC connection that a client initiates against a
server could be used by a man-in-the-middle attacker to impersonate
the authenticated user against the SAMR or LSA service on the server.
As a result, the attacker would be able to get read/write access to
the Security Account Manager database, and use this to reveal all
passwords or any other potentially sensitive information in that
database. (CVE-2016-2118)

Several flaws were found in Samba's implementation of NTLMSSP
authentication. An unauthenticated, man-in-the-middle attacker could
use this flaw to clear the encryption and integrity flags of a
connection, causing data to be transmitted in plain text. The attacker
could also force the client or server into sending data in plain text
even if encryption was explicitly requested for that connection.
(CVE-2016-2110)

It was discovered that Samba configured as a Domain Controller would
establish a secure communication channel with a machine using a
spoofed computer name. A remote attacker able to observe network
traffic could use this flaw to obtain session-related information
about the spoofed machine. (CVE-2016-2111)

It was found that Samba's LDAP implementation did not enforce
integrity protection for LDAP connections. A man-in-the-middle
attacker could use this flaw to downgrade LDAP connections to use no
integrity protection, allowing them to hijack such connections.
(CVE-2016-2112)

It was found that Samba did not validate SSL/TLS certificates in
certain connections. A man-in-the-middle attacker could use this flaw
to spoof a Samba server using a specially crafted SSL/TLS certificate.
(CVE-2016-2113)

It was discovered that Samba did not enforce Server Message Block
(SMB) signing for clients using the SMB1 protocol. A man-in-the-middle
attacker could use this flaw to modify traffic between a client and a
server. (CVE-2016-2114)

It was found that Samba did not enable integrity protection for IPC
traffic by default. A man-in-the-middle attacker could use this flaw
to view and modify the data sent between a Samba server and a client.
(CVE-2016-2115)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-686.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update samba' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ctdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ctdb-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-test-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/13");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/AmazonLinux/release")) audit(AUDIT_OS_NOT, "Amazon Linux AMI");
if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"ctdb-4.2.10-6.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ctdb-devel-4.2.10-6.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ctdb-tests-4.2.10-6.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libsmbclient-4.2.10-6.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libsmbclient-devel-4.2.10-6.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libwbclient-4.2.10-6.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libwbclient-devel-4.2.10-6.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-4.2.10-6.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-client-4.2.10-6.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-client-libs-4.2.10-6.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-common-4.2.10-6.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-common-libs-4.2.10-6.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-common-tools-4.2.10-6.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-debuginfo-4.2.10-6.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-devel-4.2.10-6.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-libs-4.2.10-6.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-pidl-4.2.10-6.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-python-4.2.10-6.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-test-4.2.10-6.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-test-devel-4.2.10-6.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-test-libs-4.2.10-6.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-winbind-4.2.10-6.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-winbind-clients-4.2.10-6.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-winbind-krb5-locator-4.2.10-6.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"samba-winbind-modules-4.2.10-6.33.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ctdb / ctdb-devel / ctdb-tests / libsmbclient / libsmbclient-devel / etc");
}
