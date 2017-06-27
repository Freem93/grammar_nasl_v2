#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0636. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78952);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/01/05 16:17:31 $");

  script_cve_id("CVE-2012-4929", "CVE-2012-6075", "CVE-2013-0166", "CVE-2013-0169", "CVE-2013-1619");
  script_bugtraq_id(55704, 57420, 57736, 57755, 57778);
  script_xref(name:"RHSA", value:"2013:0636");

  script_name(english:"RHEL 6 : rhev-hypervisor6 (RHSA-2013:0636)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated rhev-hypervisor6 package that fixes several security issues
and various bugs is now available.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The rhev-hypervisor6 package provides a Red Hat Enterprise
Virtualization Hypervisor ISO disk image. The Red Hat Enterprise
Virtualization Hypervisor is a dedicated Kernel-based Virtual Machine
(KVM) hypervisor. It includes everything necessary to run and manage
virtual machines: A subset of the Red Hat Enterprise Linux operating
environment and the Red Hat Enterprise Virtualization Agent.

Note: Red Hat Enterprise Virtualization Hypervisor is only available
for the Intel 64 and AMD64 architectures with virtualization
extensions.

A flaw was found in the way QEMU-KVM emulated the e1000 network
interface card when the host was configured to accept jumbo network
frames, and a guest using the e1000 emulated driver was not. A remote
attacker could use this flaw to crash the guest or, potentially,
execute arbitrary code with root privileges in the guest.
(CVE-2012-6075)

It was discovered that GnuTLS leaked timing information when
decrypting TLS/SSL protocol encrypted records when CBC-mode cipher
suites were used. A remote attacker could possibly use this flaw to
retrieve plain text from the encrypted packets by using a TLS/SSL
server as a padding oracle. (CVE-2013-1619)

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

This updated package provides updated components that include fixes
for various security issues. These issues have no security impact on
Red Hat Enterprise Virtualization Hypervisor itself, however. The
security fixes included in this update address the following CVE
numbers :

CVE-2013-0292 (dbus-glib issue)

CVE-2013-0228, CVE-2013-0268, and CVE-2013-0871 (kernel issues)

CVE-2013-0338 (libxml2 issue)

This update contains the builds from the following errata :

ovirt-node: RHBA-2013:0634
https://rhn.redhat.com/errata/RHBA-2013-0634.html kernel:
RHSA-2013:0630 https://rhn.redhat.com/errata/RHSA-2013-0630.html
dbus-glib: RHSA-2013:0568
https://rhn.redhat.com/errata/RHSA-2013-0568.html libcgroup:
RHBA-2013:0560 https://rhn.redhat.com/errata/RHBA-2013-0560.html vdsm:
RHBA-2013:0635 https://rhn.redhat.com/errata/RHBA-2013-0635.html
selinux-policy: RHBA-2013:0618
https://rhn.redhat.com/errata/RHBA-2013-0618.html qemu-kvm-rhev:
RHSA-2013:0610 https://rhn.redhat.com/errata/RHSA-2013-0610.html
glusterfs: RHBA-2013:0620
https://rhn.redhat.com/errata/RHBA-2013-0620.html gnutls:
RHSA-2013:0588 https://rhn.redhat.com/errata/RHSA-2013-0588.html
ipmitool: RHBA-2013:0572
https://rhn.redhat.com/errata/RHBA-2013-0572.html libxml2:
RHSA-2013:0581 https://rhn.redhat.com/errata/RHSA-2013-0581.html
openldap: RHBA-2013:0598
https://rhn.redhat.com/errata/RHBA-2013-0598.html openssl:
RHSA-2013:0587 https://rhn.redhat.com/errata/RHSA-2013-0587.html

Users of the Red Hat Enterprise Virtualization Hypervisor are advised
to upgrade to this updated package, which fixes these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4929.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-6075.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0166.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0169.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1619.html"
  );
  # https://access.redhat.com/knowledge/docs/en-US/Red_Hat_Enterprise_Linux/6/html/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?faae67f0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0636.html"
  );
  # https://access.redhat.com/knowledge/docs/en-US/Red_Hat_Enterprise_Linux/6/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?879a0985"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rhev-hypervisor6 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhev-hypervisor6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0636";
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
  if (rpm_check(release:"RHEL6", reference:"rhev-hypervisor6-6.4-20130306.2.el6_4")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rhev-hypervisor6");
  }
}
