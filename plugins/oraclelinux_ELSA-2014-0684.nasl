#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:0684 and 
# Oracle Linux Security Advisory ELSA-2014-0684 respectively.
#

include("compat.inc");

if (description)
{
  script_id(76731);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 17:25:14 $");

  script_cve_id("CVE-2014-3465", "CVE-2014-3466");
  script_bugtraq_id(67739, 67741);
  script_xref(name:"RHSA", value:"2014:0684");

  script_name(english:"Oracle Linux 7 : gnutls (ELSA-2014-0684)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2014:0684 :

Updated gnutls packages that fix two security issues are now available
for Red Hat Enterprise Linux 7.

The Red Hat Security Response Team has rated this update as having
Important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The GnuTLS library provides support for cryptographic algorithms and
for protocols such as Transport Layer Security (TLS).

A flaw was found in the way GnuTLS parsed session IDs from ServerHello
messages of the TLS/SSL handshake. A malicious server could use this
flaw to send an excessively long session ID value, which would trigger
a buffer overflow in a connecting TLS/SSL client application using
GnuTLS, causing the client application to crash or, possibly, execute
arbitrary code. (CVE-2014-3466)

A NULL pointer dereference flaw was found in the way GnuTLS parsed
X.509 certificates. A specially crafted certificate could cause a
server or client application using GnuTLS to crash. (CVE-2014-3465)

Red Hat would like to thank GnuTLS upstream for reporting these
issues. Upstream acknowledges Joonas Kuorilehto of Codenomicon as the
original reporter of CVE-2014-3466.

Users of GnuTLS are advised to upgrade to these updated packages,
which correct these issues. For the update to take effect, all
applications linked to the GnuTLS library must be restarted."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-July/004274.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnutls packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnutls-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnutls-dane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnutls-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gnutls-3.1.18-9.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gnutls-c++-3.1.18-9.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gnutls-dane-3.1.18-9.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gnutls-devel-3.1.18-9.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"gnutls-utils-3.1.18-9.el7_0")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnutls / gnutls-c++ / gnutls-dane / gnutls-devel / gnutls-utils");
}
