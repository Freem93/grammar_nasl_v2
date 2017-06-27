#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(82255);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/05/31 04:37:06 $");

  script_cve_id("CVE-2014-4341", "CVE-2014-4342", "CVE-2014-4343", "CVE-2014-4344", "CVE-2014-4345", "CVE-2014-5352", "CVE-2014-5353", "CVE-2014-9421", "CVE-2014-9422", "CVE-2014-9423");

  script_name(english:"Scientific Linux Security Update : krb5 on SL7.x x86_64");
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
"A buffer overflow was found in the KADM5 administration server
(kadmind) when it was used with an LDAP back end for the KDC database.
A remote, authenticated attacker could potentially use this flaw to
execute arbitrary code on the system running kadmind. (CVE-2014-4345)

A use-after-free flaw was found in the way the MIT Kerberos
libgssapi_krb5 library processed valid context deletion tokens. An
attacker able to make an application using the GSS-API library
(libgssapi) call the gss_process_context_token() function could use
this flaw to crash that application. (CVE-2014-5352)

If kadmind were used with an LDAP back end for the KDC database, a
remote, authenticated attacker with the permissions to set the
password policy could crash kadmind by attempting to use a named
ticket policy object as a password policy for a principal.
(CVE-2014-5353)

A double-free flaw was found in the way MIT Kerberos handled invalid
External Data Representation (XDR) data. An authenticated user could
use this flaw to crash the MIT Kerberos administration server
(kadmind), or other applications using Kerberos libraries, using
specially crafted XDR packets. (CVE-2014-9421)

It was found that the MIT Kerberos administration server (kadmind)
incorrectly accepted certain authentication requests for two-component
server principal names. A remote attacker able to acquire a key with a
particularly named principal (such as 'kad/x') could use this flaw to
impersonate any user to kadmind, and perform administrative actions as
that user. (CVE-2014-9422)

An information disclosure flaw was found in the way MIT Kerberos
RPCSEC_GSS implementation (libgssrpc) handled certain requests. An
attacker could send a specially crafted request to an application
using libgssrpc to disclose a limited portion of uninitialized memory
used by that application. (CVE-2014-9423)

Two buffer over-read flaws were found in the way MIT Kerberos handled
certain requests. A remote, unauthenticated attacker able to inject
packets into a client or server application's GSSAPI session could use
either of these flaws to crash the application. (CVE-2014-4341,
CVE-2014-4342)

A double-free flaw was found in the MIT Kerberos SPNEGO initiators. An
attacker able to spoof packets to appear as though they are from an
GSSAPI acceptor could use this flaw to crash a client application that
uses MIT Kerberos. (CVE-2014-4343)

The krb5 packages have been upgraded to upstream version 1.12, which
provides a number of bug fixes and enhancements, including :

  - Added plug-in interfaces for principal-to-username
    mapping and verifying authorization to user accounts.

  - When communicating with a KDC over a connected TCP or
    HTTPS socket, the client gives the KDC more time to
    reply before it transmits the request to another server.

This update also fixes multiple bugs, for example :

  - The Kerberos client library did not recognize certain
    exit statuses that the resolver libraries could return
    when looking up the addresses of servers configured in
    the /etc/krb5.conf file or locating Kerberos servers
    using DNS service location. The library could treat
    non-fatal return codes as fatal errors. Now, the library
    interprets the specific return codes correctly.

In addition, this update adds various enhancements. Among others :

  - Added support for contacting KDCs and kpasswd servers
    through HTTPS proxies implementing the Kerberos KDC
    Proxy (KKDCP) protocol."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1503&L=scientific-linux-errata&T=0&P=3009
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?01ec05dc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-debuginfo-1.12.2-14.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-devel-1.12.2-14.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-libs-1.12.2-14.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-pkinit-1.12.2-14.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-server-1.12.2-14.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-server-ldap-1.12.2-14.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-workstation-1.12.2-14.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
