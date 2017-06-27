#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1354. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79053);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/01/09 22:38:11 $");

  script_cve_id("CVE-2014-1568", "CVE-2014-6271", "CVE-2014-7169", "CVE-2014-7186", "CVE-2014-7187");
  script_osvdb_id(112004, 112036, 112096, 112097);
  script_xref(name:"RHSA", value:"2014:1354");
  script_xref(name:"IAVA", value:"2014-A-0142");

  script_name(english:"RHEL 6 : rhev-hypervisor6 (RHSA-2014:1354) (Shellshock)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated rhev-hypervisor6 package that fixes several security issues
is now available.

Red Hat Product Security has rated this update as having Critical
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The rhev-hypervisor6 package provides a Red Hat Enterprise
Virtualization Hypervisor ISO disk image. The Red Hat Enterprise
Virtualization Hypervisor is a dedicated Kernel-based Virtual Machine
(KVM) hypervisor. It includes everything necessary to run and manage
virtual machines: a subset of the Red Hat Enterprise Linux operating
environment and the Red Hat Enterprise Virtualization Agent.

Note: Red Hat Enterprise Virtualization Hypervisor is only available
for the Intel 64 and AMD64 architectures with virtualization
extensions.

A flaw was found in the way Bash evaluated certain specially crafted
environment variables. An attacker could use this flaw to override or
bypass environment restrictions to execute shell commands. Certain
services and applications allow remote unauthenticated attackers to
provide environment variables, allowing them to exploit this issue.
(CVE-2014-6271)

It was found that the fix for CVE-2014-6271 was incomplete, and Bash
still allowed certain characters to be injected into other
environments via specially crafted environment variables. An attacker
could potentially use this flaw to override or bypass environment
restrictions to execute shell commands. Certain services and
applications allow remote unauthenticated attackers to provide
environment variables, allowing them to exploit this issue.
(CVE-2014-7169)

A flaw was found in the way NSS parsed ASN.1 (Abstract Syntax Notation
One) input from certain RSA signatures. A remote attacker could use
this flaw to forge RSA certificates by providing a specially crafted
signature to an application using NSS. (CVE-2014-1568)

It was discovered that the fixed-sized redir_stack could be forced to
overflow in the Bash parser, resulting in memory corruption, and
possibly leading to arbitrary code execution when evaluating untrusted
input that would not otherwise be run as code. (CVE-2014-7186)

An off-by-one error was discovered in the way Bash was handling deeply
nested flow control constructs. Depending on the layout of the .bss
segment, this could allow arbitrary execution of code that would not
otherwise be executed by Bash. (CVE-2014-7187)

Red Hat would like to thank Stephane Chazelas for reporting
CVE-2014-6271, and the Mozilla project for reporting CVE-2014-1568.
Upstream acknowledges Antoine Delignat-Lavaud and Intel Product
Security Incident Response Team as the original reporters of
CVE-2014-1568. The CVE-2014-7186 and CVE-2014-7187 issues were
discovered by Florian Weimer of Red Hat Product Security.

Users of the Red Hat Enterprise Virtualization Hypervisor are advised
to upgrade to this updated package."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-1568.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-6271.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-7169.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-7186.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-7187.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-1354.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rhev-hypervisor6 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhev-hypervisor6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/02");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  rhsa = "RHSA-2014:1354";
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
  if (rpm_check(release:"RHEL6", reference:"rhev-hypervisor6-6.5-20140930.1.el6ev")) flag++;

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
