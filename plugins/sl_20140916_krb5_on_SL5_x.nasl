#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(78418);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/28 21:57:29 $");

  script_cve_id("CVE-2013-1418", "CVE-2013-6800", "CVE-2014-4341", "CVE-2014-4344");

  script_name(english:"Scientific Linux Security Update : krb5 on SL5.x i386/x86_64");
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

A buffer over-read flaw was found in the way MIT Kerberos handled
certain requests. A man-in-the-middle attacker with a valid Kerberos
ticket who is able to inject packets into a client or server
application's GSSAPI session could use this flaw to crash the
application. (CVE-2014-4341)

This update also fixes the following bugs :

  - Prior to this update, the libkrb5 library occasionally
    attempted to free already freed memory when encrypting
    credentials. As a consequence, the calling process
    terminated unexpectedly with a segmentation fault. With
    this update, libkrb5 frees memory correctly, which
    allows the credentials to be encrypted appropriately and
    thus prevents the mentioned crash.

  - Previously, when the krb5 client library was waiting for
    a response from a server, the timeout variable in
    certain cases became a negative number. Consequently,
    the client could enter a loop while checking for
    responses. With this update, the client logic has been
    modified and the described error no longer occurs.

After installing the updated packages, the krb5kdc daemon will be
restarted automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1410&L=scientific-linux-errata&T=0&P=312
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a4d4e704"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/14");
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
if (rpm_check(release:"SL5", reference:"krb5-debuginfo-1.6.1-78.el5")) flag++;
if (rpm_check(release:"SL5", reference:"krb5-devel-1.6.1-78.el5")) flag++;
if (rpm_check(release:"SL5", reference:"krb5-libs-1.6.1-78.el5")) flag++;
if (rpm_check(release:"SL5", reference:"krb5-server-1.6.1-78.el5")) flag++;
if (rpm_check(release:"SL5", reference:"krb5-server-ldap-1.6.1-78.el5")) flag++;
if (rpm_check(release:"SL5", reference:"krb5-workstation-1.6.1-78.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
