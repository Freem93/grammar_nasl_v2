#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0416. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79013);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/13 15:25:22 $");

  script_cve_id("CVE-2012-2686", "CVE-2012-4929", "CVE-2013-0166", "CVE-2013-0169", "CVE-2013-4353", "CVE-2013-6449", "CVE-2013-6450", "CVE-2014-0160");
  script_bugtraq_id(55704, 57755, 57778, 60268, 64530, 64618, 64691, 66690);
  script_osvdb_id(85927, 89848, 89865, 89866, 101347, 101597, 101843, 105465);
  script_xref(name:"RHSA", value:"2014:0416");

  script_name(english:"RHEL 6 : rhevm-spice-client (RHSA-2014:0416)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated rhevm-spice-client packages that fix multiple security issues
are now available for Red Hat Enterprise Virtualization Manager 3.

The Red Hat Security Response Team has rated this update as having
Important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Red Hat Enterprise Virtualization Manager provides access to virtual
machines using SPICE. These SPICE client packages provide the SPICE
client and usbclerk service for both Windows 32-bit operating systems
and Windows 64-bit operating systems.

The rhevm-spice-client package includes the mingw-virt-viewer Windows
SPICE client. OpenSSL, a general purpose cryptography library with a
TLS implementation, is bundled with mingw-virt-viewer. The
mingw-virt-viewer package has been updated to correct the following
issues :

An information disclosure flaw was found in the way OpenSSL handled
TLS and DTLS Heartbeat Extension packets. A malicious TLS or DTLS
client or server could send a specially crafted TLS or DTLS Heartbeat
packet to disclose a limited portion of memory per request from a
connected client or server. Note that the disclosed portions of memory
could potentially include sensitive information such as private keys.
(CVE-2014-0160)

It was discovered that OpenSSL leaked timing information when
decrypting TLS/SSL and DTLS protocol encrypted records when CBC-mode
cipher suites were used. A remote attacker could possibly use this
flaw to retrieve plain text from the encrypted packets by using a
TLS/SSL or DTLS server as a padding oracle. (CVE-2013-0169)

A NULL pointer dereference flaw was found in the way OpenSSL handled
TLS/SSL protocol handshake packets. A specially crafted handshake
packet could cause a TLS/SSL client using OpenSSL to crash.
(CVE-2013-4353)

It was discovered that the TLS/SSL protocol could leak information
about plain text when optional compression was used. An attacker able
to control part of the plain text sent over an encrypted TLS/SSL
connection could possibly use this flaw to recover other portions of
the plain text. (CVE-2012-4929)

Red Hat would like to thank the OpenSSL project for reporting
CVE-2014-0160. Upstream acknowledges Neel Mehta of Google Security as
the original reporter.

The updated mingw-virt-viewer Windows SPICE client further includes
OpenSSL security fixes that have no security impact on
mingw-virt-viewer itself. The security fixes included in this update
address the following CVE numbers :

CVE-2013-6449, CVE-2013-6450, CVE-2012-2686, and CVE-2013-0166

All Red Hat Enterprise Virtualization Manager users are advised to
upgrade to these updated packages, which address these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-0416.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0169.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4929.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4353.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0160.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-spice-client-x64-cab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-spice-client-x64-msi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-spice-client-x86-cab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-spice-client-x86-msi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_exists(rpm:"rhevm-spice-client-x64-cab-3\.3-", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-spice-client-x64-cab-3.3-12.el6_5")) flag++;
if (rpm_exists(rpm:"rhevm-spice-client-x64-msi-3\.3-", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-spice-client-x64-msi-3.3-12.el6_5")) flag++;
if (rpm_exists(rpm:"rhevm-spice-client-x86-cab-3\.3-", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-spice-client-x86-cab-3.3-12.el6_5")) flag++;
if (rpm_exists(rpm:"rhevm-spice-client-x86-msi-3\.3-", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-spice-client-x86-msi-3.3-12.el6_5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rhevm-spice-client-x64-cab-3.3 / rhevm-spice-client-x64-msi-3.3 / etc");
}
