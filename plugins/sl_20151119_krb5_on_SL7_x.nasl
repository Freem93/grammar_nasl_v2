#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(87560);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/08/02 13:41:58 $");

  script_cve_id("CVE-2014-5355", "CVE-2015-2694");

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
"It was found that the krb5_read_message() function of MIT Kerberos did
not correctly sanitize input, and could create invalid krb5_data
objects. A remote, unauthenticated attacker could use this flaw to
crash a Kerberos child process via a specially crafted request.
(CVE-2014-5355)

A flaw was found in the OTP kdcpreauth module of MIT kerberos. An
unauthenticated remote attacker could use this flaw to bypass the
requires_preauth flag on a client principal and obtain a ciphertext
encrypted in the principal's long-term key. This ciphertext could be
used to conduct an off-line dictionary attack against the user's
password. (CVE-2015-2694)

The krb5 packages have been upgraded to upstream version 1.13.2, which
provides a number of bug fixes and enhancements over the previous
version.

Notably, this update fixes the following bugs :

  - Previously, the RADIUS support (libkrad) in krb5 was
    sending krb5 authentication for Transmission Control
    Protocol (TCP) transports multiple times, accidentally
    using a code path intended to be used only for
    unreliable transport types, for example User Datagram
    Protocol (UDP) transports. A patch that fixes the
    problem by disabling manual retries for reliable
    transports, such as TCP, has been applied, and the
    correct code path is now used in this situation.

  - Attempts to use Kerberos single sign-on (SSO) to access
    SAP NetWeaver systems sometimes failed. The SAP
    NetWeaver developer trace displayed the following error
    message :

No credentials were supplied, or the credentials were unavailable or
inaccessible Unable to establish the security context

Querying SSO credential lifetime has been modified to trigger
credential acquisition, thus preventing the error from occurring. Now,
the user can successfully use Kerberos SSO for accessing SAP NetWeaver
systems."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=12350
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1553476c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-debuginfo-1.13.2-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-devel-1.13.2-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-libs-1.13.2-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-pkinit-1.13.2-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-server-1.13.2-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-server-ldap-1.13.2-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-workstation-1.13.2-10.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
