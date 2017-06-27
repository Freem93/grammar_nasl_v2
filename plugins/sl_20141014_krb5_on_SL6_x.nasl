#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(78846);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/28 21:57:29 $");

  script_cve_id("CVE-2013-1418", "CVE-2013-6800", "CVE-2014-4341", "CVE-2014-4342", "CVE-2014-4343", "CVE-2014-4344", "CVE-2014-4345");

  script_name(english:"Scientific Linux Security Update : krb5 on SL6.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that if a KDC served multiple realms, certain requests
could cause the setup_server_realm() function to dereference a NULL
pointer. A remote, unauthenticated attacker could use this flaw to
crash the KDC using a specially crafted request. (CVE-2013-1418,
CVE-2013-6800)

A NULL pointer dereference flaw was found in the MIT Kerberos SPNEGO
acceptor for continuation tokens. A remote, unauthenticated attacker
could use this flaw to crash a GSSAPI-enabled server application.
(CVE-2014-4344)

A buffer overflow was found in the KADM5 administration server
(kadmind) when it was used with an LDAP back end for the KDC database.
A remote, authenticated attacker could potentially use this flaw to
execute arbitrary code on the system running kadmind. (CVE-2014-4345)

Two buffer over-read flaws were found in the way MIT Kerberos handled
certain requests. A remote, unauthenticated attacker who is able to
inject packets into a client or server application's GSSAPI session
could use either of these flaws to crash the application.
(CVE-2014-4341, CVE-2014-4342)

A double-free flaw was found in the MIT Kerberos SPNEGO initiators. An
attacker able to spoof packets to appear as though they are from an
GSSAPI acceptor could use this flaw to crash a client application that
uses MIT Kerberos. (CVE-2014-4343)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1411&L=scientific-linux-errata&T=0&P=987
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d0a2473a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"krb5-debuginfo-1.10.3-33.el6")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-devel-1.10.3-33.el6")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-libs-1.10.3-33.el6")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-pkinit-openssl-1.10.3-33.el6")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-server-1.10.3-33.el6")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-server-ldap-1.10.3-33.el6")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-workstation-1.10.3-33.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
