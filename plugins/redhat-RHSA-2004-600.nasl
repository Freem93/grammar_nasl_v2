#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:600. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15960);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/28 17:55:17 $");

  script_cve_id("CVE-2003-0987", "CVE-2004-0885", "CVE-2004-0940");
  script_osvdb_id(10637, 12176, 12881);
  script_xref(name:"RHSA", value:"2004:600");

  script_name(english:"RHEL 2.1 : apache, mod_ssl (RHSA-2004:600)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated apache and mod_ssl packages that fix various minor security
issues and bugs in the Apache Web server are now available for Red Hat
Enterprise Linux 2.1.

The Apache HTTP Server is a powerful, full-featured, efficient, and
freely-available Web server. The mod_ssl module provides strong
cryptography for the Apache Web server via the Secure Sockets Layer
(SSL) and Transport Layer Security (TLS) protocols.

A buffer overflow was discovered in the mod_include module. This flaw
could allow a local user who is authorized to create server-side
include (SSI) files to gain the privileges of a httpd child (user
'apache'). The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-0940 to this issue.

The mod_digest module does not properly verify the nonce of a client
response by using a AuthNonce secret. This could allow a malicious
user who is able to sniff network traffic to conduct a replay attack
against a website using Digest protection. Note that mod_digest
implements an older version of the MD5 Digest Authentication
specification, which is known not to work with modern browsers. This
issue does not affect mod_auth_digest. (CVE-2003-0987).

An issue has been discovered in the mod_ssl module when configured to
use the 'SSLCipherSuite' directive in a directory or location context.
If a particular location context has been configured to require a
specific set of cipher suites, then a client is able to access that
location using any cipher suite allowed by the virtual host
configuration. (CVE-2004-0885).

Several bugs in mod_ssl were also discovered, including :

  - memory leaks in SSL variable handling

  - possible crashes in the dbm and shmht session caches

Red Hat Enterprise Linux 2.1 users of the Apache HTTP Server should
upgrade to these erratum packages, which contains Apache version
1.3.27 with backported patches correcting these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0987.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0885.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0940.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2004-600.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^2\.1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if (cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i386", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2004:600";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"apache-1.3.27-9.ent")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"apache-devel-1.3.27-9.ent")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"apache-manual-1.3.27-9.ent")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mod_ssl-2.8.12-7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache / apache-devel / apache-manual / mod_ssl");
  }
}
