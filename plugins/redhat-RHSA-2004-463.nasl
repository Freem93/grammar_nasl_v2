#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:463. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14736);
  script_version ("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/12/28 17:44:45 $");

  script_cve_id("CVE-2004-0747", "CVE-2004-0751", "CVE-2004-0786", "CVE-2004-0809");
  script_osvdb_id(9742, 9948, 9991, 9994);
  script_xref(name:"RHSA", value:"2004:463");

  script_name(english:"RHEL 3 : httpd (RHSA-2004:463)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated httpd packages that include fixes for security issues are now
available.

The Apache HTTP server is a powerful, full-featured, efficient, and
freely-available Web server.

Four issues have been discovered affecting releases of the Apache HTTP
2.0 Server, up to and including version 2.0.50 :

Testing using the Codenomicon HTTP Test Tool performed by the Apache
Software Foundation security group and Red Hat uncovered an input
validation issue in the IPv6 URI parsing routines in the apr-util
library. If a remote attacker sent a request including a carefully
crafted URI, an httpd child process could be made to crash. This issue
is not believed to allow arbitrary code execution on Red Hat
Enterprise Linux. This issue also does not represent a significant
denial of service attack as requests will continue to be handled by
other Apache child processes. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2004-0786 to this
issue.

The Swedish IT Incident Centre (SITIC) reported a buffer overflow in
the expansion of environment variables during configuration file
parsing. This issue could allow a local user to gain 'apache'
privileges if an httpd process can be forced to parse a carefully
crafted .htaccess file written by a local user. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2004-0747 to this issue.

An issue was discovered in the mod_ssl module which could be triggered
if the server is configured to allow proxying to a remote SSL server.
A malicious remote SSL server could force an httpd child process to
crash by sending a carefully crafted response header. This issue is
not believed to allow execution of arbitrary code. This issue also
does not represent a significant Denial of Service attack as requests
will continue to be handled by other Apache child processes. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2004-0751 to this issue.

An issue was discovered in the mod_dav module which could be triggered
for a location where WebDAV authoring access has been configured. A
malicious remote client which is authorized to use the LOCK method
could force an httpd child process to crash by sending a particular
sequence of LOCK requests. This issue does not allow execution of
arbitrary code. This issue also does not represent a significant
Denial of Service attack as requests will continue to be handled by
other Apache child processes. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2004-0809 to this
issue.

Users of the Apache HTTP server should upgrade to these updated
packages, which contain backported patches that address these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0747.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0751.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0786.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0809.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2004-463.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd, httpd-devel and / or mod_ssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/15");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/02");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2004:463";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL3", reference:"httpd-2.0.46-40.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"httpd-devel-2.0.46-40.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mod_ssl-2.0.46-40.ent")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-devel / mod_ssl");
  }
}
