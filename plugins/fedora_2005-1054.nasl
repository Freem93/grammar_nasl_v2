#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-1054.
#

include("compat.inc");

if (description)
{
  script_id(20166);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/21 21:09:32 $");

  script_cve_id("CVE-2005-2672");
  script_xref(name:"FEDORA", value:"2005-1054");

  script_name(english:"Fedora Core 3 : lm_sensors-2.8.7-2.FC3.1 (2005-1054)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The lm_sensors package includes a collection of modules for general
SMBus access and hardware monitoring. NOTE: this package requires
special support which is not in standard 2.2-vintage kernels.

A bug was found in the pwmconfig tool which uses temporary files in an
insecure manner. The pwconfig tool writes a configuration file which
may be world readable for a short period of time. This file contains
various information about the setup of lm_sensors on that machine. It
could be modified within the short window to contain configuration
data that would either render lm_sensors unusable or in the worst case
even hang the machine resulting in a DoS. The Common Vulnerabilities
and Exposures project has assigned the name CVE-2005-2672 to this
issue.

Users of lm_sensors are advised to upgrade to these updated packages,
which contain a patch which resolves this issue.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-November/001548.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3b21dc4c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected lm_sensors, lm_sensors-debuginfo and / or
lm_sensors-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:lm_sensors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:lm_sensors-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:lm_sensors-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 3.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC3", reference:"lm_sensors-2.8.7-2.FC3.1")) flag++;
if (rpm_check(release:"FC3", reference:"lm_sensors-debuginfo-2.8.7-2.FC3.1")) flag++;
if (rpm_check(release:"FC3", reference:"lm_sensors-devel-2.8.7-2.FC3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lm_sensors / lm_sensors-debuginfo / lm_sensors-devel");
}
