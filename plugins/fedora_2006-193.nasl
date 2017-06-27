#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2006-193.
#

include("compat.inc");

if (description)
{
  script_id(21190);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/10/21 21:46:26 $");

  script_cve_id("CVE-2006-0058");
  script_xref(name:"FEDORA", value:"2006-193");

  script_name(english:"Fedora Core 5 : sendmail-8.13.6-0.FC5.1 (2006-193)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fixes CVE-2006-0058 :

A flaw in the handling of asynchronous signals. A remote attacker may
be able to exploit a race condition to execute arbitrary code as root.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2006-April/001981.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?47521fcc"
  );
  # https://lists.fedoraproject.org/pipermail/announce/2006-March/001897.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?25a4449a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:sendmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:sendmail-cf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:sendmail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:sendmail-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:sendmail-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/04/08");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 5.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC5", reference:"sendmail-8.13.6-0.FC5.1")) flag++;
if (rpm_check(release:"FC5", reference:"sendmail-cf-8.13.6-0.FC5.1")) flag++;
if (rpm_check(release:"FC5", reference:"sendmail-debuginfo-8.13.6-0.FC5.1")) flag++;
if (rpm_check(release:"FC5", reference:"sendmail-devel-8.13.6-0.FC5.1")) flag++;
if (rpm_check(release:"FC5", reference:"sendmail-doc-8.13.6-0.FC5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sendmail / sendmail-cf / sendmail-debuginfo / sendmail-devel / etc");
}
