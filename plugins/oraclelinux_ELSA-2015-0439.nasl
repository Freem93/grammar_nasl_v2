#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:0439 and 
# Oracle Linux Security Advisory ELSA-2015-0439 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(81805);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/06 17:02:16 $");

  script_cve_id("CVE-2014-4341", "CVE-2014-4342", "CVE-2014-4343", "CVE-2014-4344", "CVE-2014-4345", "CVE-2014-5352", "CVE-2014-5353", "CVE-2014-9421", "CVE-2014-9422", "CVE-2014-9423");
  script_bugtraq_id(63555, 63770, 68908, 68909, 69159, 69160, 69168, 71679, 71680, 72494, 72495, 72496, 72503);
  script_osvdb_id(108748, 108751, 109389, 109390, 109908, 115960, 117920, 117921, 117922, 117923);
  script_xref(name:"RHSA", value:"2015:0439");

  script_name(english:"Oracle Linux 7 : krb5 (ELSA-2015-0439)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:0439 :

Updated krb5 packages that fix multiple security issues, several bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Kerberos is a networked authentication system which allows clients and
servers to authenticate to each other with the help of a trusted third
party, the Kerberos KDC.

A NULL pointer dereference flaw was found in the MIT Kerberos SPNEGO
acceptor for continuation tokens. A remote, unauthenticated attacker
could use this flaw to crash a GSSAPI-enabled server application.
(CVE-2014-4344)

A buffer overflow was found in the KADM5 administration server
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

Red Hat would like to thank the MIT Kerberos project for reporting the
CVE-2014-5352, CVE-2014-9421, CVE-2014-9422, and CVE-2014-9423 issues.
MIT Kerberos project acknowledges Nico Williams for helping with the
analysis of CVE-2014-5352.

The krb5 packages have been upgraded to upstream version 1.12, which
provides a number of bug fixes and enhancements, including :

* Added plug-in interfaces for principal-to-username mapping and
verifying authorization to user accounts.

* When communicating with a KDC over a connected TCP or HTTPS socket,
the client gives the KDC more time to reply before it transmits the
request to another server. (BZ#1049709, BZ#1127995)

This update also fixes multiple bugs, for example :

* The Kerberos client library did not recognize certain exit statuses
that the resolver libraries could return when looking up the addresses
of servers configured in the /etc/krb5.conf file or locating Kerberos
servers using DNS service location. The library could treat non-fatal
return codes as fatal errors. Now, the library interprets the specific
return codes correctly. (BZ#1084068, BZ#1109102)

In addition, this update adds various enhancements. Among others :

* Added support for contacting KDCs and kpasswd servers through HTTPS
proxies implementing the Kerberos KDC Proxy (KKDCP) protocol.
(BZ#1109919)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-March/004886.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"krb5-devel-1.12.2-14.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"krb5-libs-1.12.2-14.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"krb5-pkinit-1.12.2-14.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"krb5-server-1.12.2-14.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"krb5-server-ldap-1.12.2-14.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"krb5-workstation-1.12.2-14.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-devel / krb5-libs / krb5-pkinit / krb5-server / etc");
}
