#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-0704.
#

include("compat.inc");

if (description)
{
  script_id(27675);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/10/21 21:46:28 $");

  script_cve_id("CVE-2006-5752", "CVE-2007-1862", "CVE-2007-1863", "CVE-2007-3304");
  script_xref(name:"FEDORA", value:"2007-0704");

  script_name(english:"Fedora 7 : httpd-2.2.4-4.1.fc7 (2007-0704)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Apache HTTP Server did not verify that a process was an Apache
child process before sending it signals. A local attacker with the
ability to run scripts on the Apache HTTP Server could manipulate the
scoreboard and cause arbitrary processes to be terminated which could
lead to a denial of service (CVE-2007-3304). This issue is not
exploitable on Fedora if using the default SELinux targeted policy.

A flaw was found in the Apache HTTP Server mod_status module. On sites
where the server-status page is publicly accessible and ExtendedStatus
is enabled this could lead to a cross-site scripting attack. On Fedora
the server-status page is not enabled by default and it is best
practice to not make this publicly available. (CVE-2006-5752)

A bug was found in the Apache HTTP Server mod_cache module. On sites
where caching is enabled, a remote attacker could send a carefully
crafted request that would cause the Apache child process handling
that request to crash. This could lead to a denial of service if using
a threaded Multi-Processing Module. (CVE-2007-1863)

A bug was found in the mod_mem_cache module. On sites where caching is
enabled using this module, an information leak could occur which
revealed portions of sensitive memory to remote users. (CVE-2007-1862)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-June/002337.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c9b1211"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"httpd-2.2.4-4.1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"httpd-debuginfo-2.2.4-4.1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"httpd-devel-2.2.4-4.1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"httpd-manual-2.2.4-4.1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"mod_ssl-2.2.4-4.1.fc7")) flag++;


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
