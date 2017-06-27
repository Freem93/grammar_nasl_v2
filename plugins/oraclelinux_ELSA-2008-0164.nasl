#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2008:0164 and 
# Oracle Linux Security Advisory ELSA-2008-0164 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67664);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/07 20:57:49 $");

  script_cve_id("CVE-2007-5901", "CVE-2007-5971", "CVE-2008-0062", "CVE-2008-0063", "CVE-2008-0947");
  script_bugtraq_id(26750, 28302, 28303);
  script_osvdb_id(43341, 43342, 43343, 43345, 43346);
  script_xref(name:"RHSA", value:"2008:0164");

  script_name(english:"Oracle Linux 5 : krb5 (ELSA-2008-0164)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2008:0164 :

Updated krb5 packages that resolve several issues and fix multiple
bugs are now available for Red Hat Enterprise Linux 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Kerberos is a network authentication system which allows clients and
servers to authenticate to each other through use of symmetric
encryption and a trusted third party, the KDC.

A flaw was found in the way the MIT Kerberos Authentication Service
and Key Distribution Center server (krb5kdc) handled Kerberos v4
protocol packets. An unauthenticated remote attacker could use this
flaw to crash the krb5kdc daemon, disclose portions of its memory, or
possibly execute arbitrary code using malformed or truncated Kerberos
v4 protocol requests. (CVE-2008-0062, CVE-2008-0063)

This issue only affected krb5kdc with Kerberos v4 protocol
compatibility enabled, which is the default setting on Red Hat
Enterprise Linux 4. Kerberos v4 protocol support can be disabled by
adding 'v4_mode=none' (without the quotes) to the '[kdcdefaults]'
section of /var/kerberos/krb5kdc/kdc.conf.

Jeff Altman of Secure Endpoints discovered a flaw in the RPC library
as used by MIT Kerberos kadmind server. An unauthenticated remote
attacker could use this flaw to crash kadmind or possibly execute
arbitrary code. This issue only affected systems with certain resource
limits configured and did not affect systems using default resource
limits used by Red Hat Enterprise Linux 5. (CVE-2008-0947)

Red Hat would like to thank MIT for reporting these issues.

Multiple memory management flaws were discovered in the GSSAPI library
used by MIT Kerberos. These flaws could possibly result in use of
already freed memory or an attempt to free already freed memory blocks
(double-free flaw), possibly causing a crash or arbitrary code
execution. (CVE-2007-5901, CVE-2007-5971)

In addition to the security issues resolved above, the following bugs
were also fixed :

* delegated krb5 credentials were not properly stored when SPNEGO was
the underlying mechanism during GSSAPI authentication. Consequently,
applications attempting to copy delegated Kerberos 5 credentials into
a credential cache received an 'Invalid credential was supplied'
message rather than a copy of the delegated credentials. With this
update, SPNEGO credentials can be properly searched, allowing
applications to copy delegated credentials as expected.

* applications can initiate context acceptance (via
gss_accept_sec_context) without passing a ret_flags value that would
indicate that credentials were delegated. A delegated credential
handle should have been returned in such instances. This updated
package adds a temp_ret_flag that stores the credential status in the
event no other ret_flags value is passed by an application calling
gss_accept_sec_context.

* kpasswd did not fallback to TCP on receipt of certain errors, or
when a packet was too big for UDP. This update corrects this.

* when the libkrb5 password-routine generated a set-password or
change-password request, incorrect sequence numbers were generated for
all requests subsequent to the first request. This caused password
change requests to fail if the primary server was unavailable. This
updated package corrects this by saving the sequence number value
after the AP-REQ data is built and restoring this value before the
request is generated.

* when a user's password expired, kinit would not prompt that user to
change the password, instead simply informing the user their password
had expired. This update corrects this behavior: kinit now prompts for
a new password to be set when a password has expired.

All krb5 users are advised to upgrade to these updated packages, which
contain backported fixes to address these vulnerabilities and fix
these bugs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-March/000547.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"krb5-devel-1.6.1-17.el5_1.1")) flag++;
if (rpm_check(release:"EL5", reference:"krb5-libs-1.6.1-17.el5_1.1")) flag++;
if (rpm_check(release:"EL5", reference:"krb5-server-1.6.1-17.el5_1.1")) flag++;
if (rpm_check(release:"EL5", reference:"krb5-workstation-1.6.1-17.el5_1.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-devel / krb5-libs / krb5-server / krb5-workstation");
}
