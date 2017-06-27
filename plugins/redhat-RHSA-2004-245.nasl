#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:245. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12506);
  script_version ("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/12/28 17:44:44 $");

  script_cve_id("CVE-2004-0488", "CVE-2004-0492");
  script_bugtraq_id(10508);
  script_osvdb_id(6472, 6839);
  script_xref(name:"RHSA", value:"2004:245");

  script_name(english:"RHEL 2.1 : apache, mod_ssl (RHSA-2004:245)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated httpd and mod_ssl packages that fix minor security issues in
the Apache Web server are now available for Red Hat Enterprise Linux
2.1.

The Apache HTTP Server is a powerful, full-featured, efficient, and
freely-available Web server.

A buffer overflow was found in the Apache proxy module, mod_proxy,
which can be triggered by receiving an invalid Content-Length header.
In order to exploit this issue, an attacker would need an Apache
installation that was configured as a proxy to connect to a malicious
site. This would cause the Apache child processing the request to
crash. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-0492 to this issue.

On Red Hat Enterprise Linux platforms Red Hat believes this issue
cannot lead to remote code execution. This issue also does not
represent a Denial of Service attack as requests will continue to be
handled by other Apache child processes.

A stack-based buffer overflow was discovered in mod_ssl which can be
triggered if using the FakeBasicAuth option. If mod_ssl is sent a
client certificate with a subject DN field longer than 6000
characters, a stack overflow can occur if FakeBasicAuth has been
enabled. In order to exploit this issue the carefully crafted
malicious certificate would have to be signed by a Certificate
Authority which mod_ssl is configured to trust. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2004-0488 to this issue.

This update also fixes a DNS handling bug in mod_proxy.

The mod_auth_digest module is now included in the Apache package and
should be used instead of mod_digest for sites requiring Digest
authentication.

Red Hat Enterprise Linux 2.1 users of the Apache HTTP Server should
upgrade to these erratum packages, which contains Apache version
1.3.27 with backported patches correcting these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0488.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0492.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.apacheweek.com/issues/04-06-11#security"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2004-245.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/05/17");
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
  rhsa = "RHSA-2004:245";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"apache-1.3.27-8.ent")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"apache-devel-1.3.27-8.ent")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"apache-manual-1.3.27-8.ent")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"mod_ssl-2.8.12-4")) flag++;

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
