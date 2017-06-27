#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0041. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78994);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/06 15:40:56 $");

  script_cve_id("CVE-2013-4353", "CVE-2013-5605", "CVE-2013-5606", "CVE-2013-6449");
  script_bugtraq_id(63737, 63738, 64530, 64691);
  script_xref(name:"RHSA", value:"2014:0041");

  script_name(english:"RHEL 6 : rhev-hypervisor6 (RHSA-2014:0041)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated rhev-hypervisor6 package that fixes multiple security
issues is now available.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The rhev-hypervisor6 package provides a Red Hat Enterprise
Virtualization Hypervisor ISO disk image. The Red Hat Enterprise
Virtualization Hypervisor is a dedicated Kernel-based Virtual Machine
(KVM) hypervisor. It includes everything necessary to run and manage
virtual machines: a subset of the Red Hat Enterprise Linux operating
environment and the Red Hat Enterprise Virtualization Agent.

Note: Red Hat Enterprise Virtualization Hypervisor is only available
for the Intel 64 and AMD64 architectures with virtualization
extensions.

Upgrade Note: If you upgrade Red Hat Enterprise Virtualization
Hypervisor 6.4 to version 6.5 through the 3.3 Manager administration
portal, configuration of the previous system appears to be lost when
reported in the TUI. However, this is an issue in the TUI itself, not
in the upgrade process; the configuration of the system is not
affected.

A flaw was found in the way NSS handled invalid handshake packets. A
remote attacker could use this flaw to cause a TLS/SSL client using
NSS to crash or, possibly, execute arbitrary code with the privileges
of the user running the application. (CVE-2013-5605)

A flaw was found in the way OpenSSL determined which hashing algorithm
to use when TLS protocol version 1.2 was enabled. This could possibly
cause OpenSSL to use an incorrect hashing algorithm, leading to a
crash of an application using the library. (CVE-2013-6449)

A NULL pointer dereference flaw was found in the way OpenSSL handled
TLS/SSL protocol handshake packets. A specially crafted handshake
packet could cause a TLS/SSL client using OpenSSL to crash.
(CVE-2013-4353)

It was discovered that NSS did not reject certificates with
incompatible key usage constraints when validating them while the
verifyLog feature was enabled. An application using the NSS
certificate validation API could accept an invalid certificate.
(CVE-2013-5606)

Red Hat would like to thank the Mozilla project for reporting
CVE-2013-5606. Upstream acknowledges Camilo Viecco as the original
reporter of CVE-2013-5606.

This updated package provides updated components that include fixes
for various security issues. These issues have no security impact on
Red Hat Enterprise Virtualization Hypervisor itself, however. The
security fixes included in this update address the following CVE
numbers :

CVE-2013-6462 (libXfont issue)

CVE-2013-6629, and CVE-2013-6630 (libjpeg-turbo issues)

CVE-2013-1739, CVE-2013-1741, and CVE-2013-5607 (nss, nspr issues)

CVE-2013-6450 (openssl issue)

CVE-2013-6425 (pixman issue)

Users of the Red Hat Enterprise Virtualization Hypervisor are advised
to upgrade to this updated package, which corrects these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4353.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5605.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5606.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-6449.html"
  );
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux/6/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64c6b598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-0041.html"
  );
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6b506c4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rhev-hypervisor6 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhev-hypervisor6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/21");
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
  rhsa = "RHSA-2014:0041";
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
  if (rpm_check(release:"RHEL6", reference:"rhev-hypervisor6-6.5-20140112.0.el6ev")) flag++;

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
