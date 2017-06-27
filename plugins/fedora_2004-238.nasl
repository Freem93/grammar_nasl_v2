#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2004-238.
#

include("compat.inc");

if (description)
{
  script_id(14209);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/10/21 21:09:31 $");

  script_cve_id("CVE-2004-0597");
  script_xref(name:"FEDORA", value:"2004-238");

  script_name(english:"Fedora Core 2 : libpng10-1.0.15-8 (2004-238)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The libpng package contains a library of functions for creating and
manipulating PNG (Portable Network Graphics) image format files.

During a source code audit, Chris Evans discovered several buffer
overflows in libpng. An attacker could create a carefully crafted PNG
file in such a way that it would cause an application linked with
libpng to execute arbitrary code when the file was opened by a victim.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2004-0597 to these issues. 

In addition, this audit discovered a potential NULL pointer
dereference in libpng (CVE-2004-0598) and several integer overflow
issues (CVE-2004-0599). An attacker could create a carefully crafted
PNG file in such a way that it would cause an application linked with
libpng to crash when the file was opened by the victim.

Red Hat would like to thank Chris Evans for discovering these issues.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2004-August/000246.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d01ab5cf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libpng10, libpng10-debuginfo and / or
libpng10-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libpng10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libpng10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libpng10-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^2([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 2.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC2", reference:"libpng10-1.0.15-8")) flag++;
if (rpm_check(release:"FC2", reference:"libpng10-debuginfo-1.0.15-8")) flag++;
if (rpm_check(release:"FC2", reference:"libpng10-devel-1.0.15-8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpng10 / libpng10-debuginfo / libpng10-devel");
}
