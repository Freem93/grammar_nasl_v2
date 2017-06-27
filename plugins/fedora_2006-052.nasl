#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2006-052.
#

include("compat.inc");

if (description)
{
  script_id(20757);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 21:38:06 $");

  script_cve_id("CVE-2005-2970", "CVE-2005-3352", "CVE-2005-3357");
  script_xref(name:"FEDORA", value:"2006-052");

  script_name(english:"Fedora Core 4 : httpd-2.0.54-10.3 (2006-052)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update includes fixes for three security issues in the Apache
HTTP Server.

A memory leak in the worker MPM could allow remote attackers to cause
a denial of service (memory consumption) via aborted connections,
which prevents the memory for the transaction pool from being reused
for other connections. The Common Vulnerabilities and Exposures
project assigned the name CVE-2005-2970 to this issue. This
vulnerability only affects users who are using the non-default worker
MPM.

A flaw in mod_imap when using the Referer directive with image maps
was discovered. With certain site configurations, a remote attacker
could perform a cross-site scripting attack if a victim can be forced
to visit a malicious URL using certain web browsers. (CVE-2005-3352)

A NULL pointer dereference flaw in mod_ssl was discovered affecting
server configurations where an SSL virtual host is configured with
access control and a custom 400 error document. A remote attacker
could send a carefully crafted request to trigger this issue which
would lead to a crash. This crash would only be a denial of service if
using the non-default worker MPM. (CVE-2005-3357)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2006-January/001765.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?68f387ab"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 4.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC4", reference:"httpd-2.0.54-10.3")) flag++;
if (rpm_check(release:"FC4", reference:"httpd-debuginfo-2.0.54-10.3")) flag++;
if (rpm_check(release:"FC4", reference:"httpd-devel-2.0.54-10.3")) flag++;
if (rpm_check(release:"FC4", reference:"httpd-manual-2.0.54-10.3")) flag++;
if (rpm_check(release:"FC4", reference:"mod_ssl-2.0.54-10.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-debuginfo / httpd-devel / httpd-manual / mod_ssl");
}
