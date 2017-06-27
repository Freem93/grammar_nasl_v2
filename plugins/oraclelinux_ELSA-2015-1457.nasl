#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:1457 and 
# Oracle Linux Security Advisory ELSA-2015-1457 respectively.
#

include("compat.inc");

if (description)
{
  script_id(85109);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2015/12/04 14:38:00 $");

  script_cve_id("CVE-2014-8155", "CVE-2015-0282", "CVE-2015-0294");
  script_bugtraq_id(73119, 73162, 73317);
  script_osvdb_id(118749, 119020, 119405);
  script_xref(name:"RHSA", value:"2015:1457");

  script_name(english:"Oracle Linux 6 : gnutls (ELSA-2015-1457)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:1457 :

Updated gnutls packages that fix three security issues and one bug are
now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The GnuTLS library provides support for cryptographic algorithms and
for protocols such as Transport Layer Security (TLS).

It was found that GnuTLS did not check activation and expiration dates
of CA certificates. This could cause an application using GnuTLS to
incorrectly accept a certificate as valid when its issuing CA is
already expired. (CVE-2014-8155)

It was found that GnuTLS did not verify whether a hashing algorithm
listed in a signature matched the hashing algorithm listed in the
certificate. An attacker could create a certificate that used a
different hashing algorithm than it claimed, possibly causing GnuTLS
to use an insecure, disallowed hashing algorithm during certificate
verification. (CVE-2015-0282)

It was discovered that GnuTLS did not check if all sections of X.509
certificates indicate the same signature algorithm. This flaw, in
combination with a different flaw, could possibly lead to a bypass of
the certificate signature check. (CVE-2015-0294)

The CVE-2014-8155 issue was discovered by Marcel Kolaja of Red Hat.
The CVE-2015-0282 and CVE-2015-0294 issues were discovered by Nikos
Mavrogiannopoulos of the Red Hat Security Technologies Team.

This update also fixes the following bug :

* Previously, under certain circumstances, the certtool utility could
generate X.509 certificates which contained a negative modulus.
Consequently, such certificates could have interoperation problems
with the software using them. The bug has been fixed, and certtool no
longer generates X.509 certificates containing a negative modulus.
(BZ#1036385)

Users of gnutls are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-July/005234.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnutls packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnutls-guile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnutls-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"gnutls-2.8.5-18.el6")) flag++;
if (rpm_check(release:"EL6", reference:"gnutls-devel-2.8.5-18.el6")) flag++;
if (rpm_check(release:"EL6", reference:"gnutls-guile-2.8.5-18.el6")) flag++;
if (rpm_check(release:"EL6", reference:"gnutls-utils-2.8.5-18.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnutls / gnutls-devel / gnutls-guile / gnutls-utils");
}
