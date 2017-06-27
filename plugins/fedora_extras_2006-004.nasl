#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted and adapted from the Fedora Security Advisory.
#

include("compat.inc");

if (description)
{
  script_id(62278);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/19 23:22:35 $");

  script_cve_id("CVE-2006-4806", "CVE-2006-4807", "CVE-2006-4808", "CVE-2006-4809");

  script_name(english:"Fedora Extras : imlib2-1.2.1-2 (2006-004)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"M. Joonas Pihlaja discovered that imlib2 did not sufficiently verify
the validity of ARGB, JPG, LBM, PNG, PNM, TGA, and TIFF images. If a
user were tricked into viewing or processing a specially crafted image
with an application that uses imlib2, the flaws could be exploited to
execute arbitrary code with the user's privileges.

Fedora Extras versions earlier then the versions mentioned above are
vulnerable to this problem, upgrade to fix this vulnerability.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2006-November/000846.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?81dd7ca0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected imlib2 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:imlib2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(3|4|5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 3.x / 4.x / 5.x / 6.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC3", reference:"imlib2-1.2.1-2")) flag++;

if (rpm_check(release:"FC4", reference:"imlib2-1.2.1-2")) flag++;

if (rpm_check(release:"FC5", reference:"imlib2-1.3.0-3")) flag++;

if (rpm_check(release:"FC6", reference:"imlib2-1.3.0-3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "imlib2");
}
