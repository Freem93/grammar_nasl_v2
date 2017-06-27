#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-1473.
#

include("compat.inc");

if (description)
{
  script_id(64448);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/19 21:12:41 $");

  script_cve_id("CVE-2012-5127");
  script_bugtraq_id(56413);
  script_xref(name:"FEDORA", value:"2013-1473");

  script_name(english:"Fedora 17 : OpenImageIO-1.0.11-2.fc17 / gdal-1.9.1-14.fc17.1 / leptonica-1.69-5.fc17 / etc (2013-1473)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security libwebp release, where an integer overflow allows remote
attackers to cause a denial of service (out-of-bounds read) or
possibly have unspecified other impact via a crafted WebP image.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=875071"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-February/098246.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?84c0bfb7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-February/098247.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a9ffb2c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-February/098248.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fae6934a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-February/098249.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc7a9da6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:OpenImageIO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:leptonica");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libwebp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:17");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^17([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 17.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC17", reference:"OpenImageIO-1.0.11-2.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"gdal-1.9.1-14.fc17.1")) flag++;
if (rpm_check(release:"FC17", reference:"leptonica-1.69-5.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"libwebp-0.2.1-1.fc17")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenImageIO / gdal / leptonica / libwebp");
}
