#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1184. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40439);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2017/01/03 17:27:02 $");

  script_cve_id("CVE-2009-2404", "CVE-2009-2408", "CVE-2009-2409");
  script_xref(name:"RHSA", value:"2009:1184");

  script_name(english:"RHEL 4 : nspr and nss (RHSA-2009:1184)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nspr and nss packages that fix security issues and a bug are
now available for Red Hat Enterprise Linux 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Netscape Portable Runtime (NSPR) provides platform independence for
non-GUI operating system facilities. These facilities include threads,
thread synchronization, normal file and network I/O, interval timing,
calendar time, basic memory management (malloc and free), and shared
library linking.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications. Applications built with NSS can support SSLv2,
SSLv3, TLS, and other security standards.

These updated packages upgrade NSS from the previous version, 3.12.2,
to a prerelease of version 3.12.4. The version of NSPR has also been
upgraded from 4.7.3 to 4.7.4.

Moxie Marlinspike reported a heap overflow flaw in a regular
expression parser in the NSS library used by browsers such as Mozilla
Firefox to match common names in certificates. A malicious website
could present a carefully-crafted certificate in such a way as to
trigger the heap overflow, leading to a crash or, possibly, arbitrary
code execution with the permissions of the user running the browser.
(CVE-2009-2404)

Note: in order to exploit this issue without further user interaction
in Firefox, the carefully-crafted certificate would need to be signed
by a Certificate Authority trusted by Firefox, otherwise Firefox
presents the victim with a warning that the certificate is untrusted.
Only if the user then accepts the certificate will the overflow take
place.

Dan Kaminsky discovered flaws in the way browsers such as Firefox
handle NULL characters in a certificate. If an attacker is able to get
a carefully-crafted certificate signed by a Certificate Authority
trusted by Firefox, the attacker could use the certificate during a
man-in-the-middle attack and potentially confuse Firefox into
accepting it by mistake. (CVE-2009-2408)

Dan Kaminsky found that browsers still accept certificates with MD2
hash signatures, even though MD2 is no longer considered a
cryptographically strong algorithm. This could make it easier for an
attacker to create a malicious certificate that would be treated as
trusted by a browser. NSS now disables the use of MD2 and MD4
algorithms inside signatures by default. (CVE-2009-2409)

These version upgrades also provide a fix for the following bug :

* SSL client authentication failed against an Apache server when it
was using the mod_nss module and configured for NSSOCSP. On the client
side, the user agent received an error message that referenced 'Error
Code: -12271' and stated that establishing an encrypted connection had
failed because the certificate had been rejected by the host.

On the server side, the nss_error_log under /var/log/httpd/ contained
the following message :

[error] Re-negotiation handshake failed: Not accepted by client!?

Also, /var/log/httpd/error_log contained this error :

SSL Library Error: -8071 The OCSP server experienced an internal error

With these updated packages, the dependency problem which caused this
failure has been resolved so that SSL client authentication with an
Apache web server using mod_nss which is configured for NSSOCSP
succeeds as expected. Note that if the presented client certificate is
expired, then access is denied, the user agent is presented with an
error message about the invalid certificate, and the OCSP queries are
seen in the OCSP responder. Also, similar OCSP status verification
happens for SSL server certificates used in Apache upon instance start
or restart. (BZ#508027)

All users of nspr and nss are advised to upgrade to these updated
packages, which resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-2404.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-2408.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-2409.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1184.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2009:1184";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL4", reference:"nspr-4.7.4-1.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"nspr-devel-4.7.4-1.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"nss-3.12.3.99.3-1.el4_8.2")) flag++;

  if (rpm_check(release:"RHEL4", reference:"nss-devel-3.12.3.99.3-1.el4_8.2")) flag++;

  if (rpm_check(release:"RHEL4", reference:"nss-tools-3.12.3.99.3-1.el4_8.2")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nspr / nspr-devel / nss / nss-devel / nss-tools");
  }
}
