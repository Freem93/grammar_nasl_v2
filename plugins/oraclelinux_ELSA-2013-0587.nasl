#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0587 and 
# Oracle Linux Security Advisory ELSA-2013-0587 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68768);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/12/01 17:16:03 $");

  script_cve_id("CVE-2012-4929", "CVE-2013-0166", "CVE-2013-0169");
  script_bugtraq_id(55704, 57755, 57778);
  script_osvdb_id(85927, 89848, 89865, 113864);
  script_xref(name:"RHSA", value:"2013:0587");

  script_name(english:"Oracle Linux 5 / 6 : openssl (ELSA-2013-0587)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:0587 :

Updated openssl packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL
v2/v3) and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

It was discovered that OpenSSL leaked timing information when
decrypting TLS/SSL and DTLS protocol encrypted records when CBC-mode
cipher suites were used. A remote attacker could possibly use this
flaw to retrieve plain text from the encrypted packets by using a
TLS/SSL or DTLS server as a padding oracle. (CVE-2013-0169)

A NULL pointer dereference flaw was found in the OCSP response
verification in OpenSSL. A malicious OCSP server could use this flaw
to crash applications performing OCSP verification by sending a
specially crafted response. (CVE-2013-0166)

It was discovered that the TLS/SSL protocol could leak information
about plain text when optional compression was used. An attacker able
to control part of the plain text sent over an encrypted TLS/SSL
connection could possibly use this flaw to recover other portions of
the plain text. (CVE-2012-4929)

Note: This update disables zlib compression, which was previously
enabled in OpenSSL by default. Applications using OpenSSL now need to
explicitly enable zlib compression to use it.

It was found that OpenSSL read certain environment variables even when
used by a privileged (setuid or setgid) application. A local attacker
could use this flaw to escalate their privileges. No application
shipped with Red Hat Enterprise Linux 5 and 6 was affected by this
problem. (BZ#839735)

All OpenSSL users should upgrade to these updated packages, which
contain backported patches to resolve these issues. For the update to
take effect, all services linked to the OpenSSL library must be
restarted, or the system rebooted."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-March/003326.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-March/003327.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"openssl-0.9.8e-26.el5_9.1")) flag++;
if (rpm_check(release:"EL5", reference:"openssl-devel-0.9.8e-26.el5_9.1")) flag++;
if (rpm_check(release:"EL5", reference:"openssl-perl-0.9.8e-26.el5_9.1")) flag++;

if (rpm_check(release:"EL6", reference:"openssl-1.0.0-27.el6_4.2")) flag++;
if (rpm_check(release:"EL6", reference:"openssl-devel-1.0.0-27.el6_4.2")) flag++;
if (rpm_check(release:"EL6", reference:"openssl-perl-1.0.0-27.el6_4.2")) flag++;
if (rpm_check(release:"EL6", reference:"openssl-static-1.0.0-27.el6_4.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-devel / openssl-perl / openssl-static");
}
