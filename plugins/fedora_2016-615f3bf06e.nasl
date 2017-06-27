#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-615f3bf06e.
#

include("compat.inc");

if (description)
{
  script_id(92532);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/10/18 16:52:28 $");

  script_cve_id("CVE-2016-5766", "CVE-2016-6128", "CVE-2016-6132", "CVE-2016-6207", "CVE-2016-6214");
  script_xref(name:"FEDORA", value:"2016-615f3bf06e");

  script_name(english:"Fedora 24 : gd (2016-615f3bf06e)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**LibGD 2.2.3 release**

Security related fixes: This flaw is caused by loading data from
external sources (file, custom ctx, etc) and are hard to validate
before calling libgd APIs :

  - fix php bug php#72339, Integer Overflow in _gd2GetHeader
    (CVE-2016-5766)

  - bug #248, fix Out-Of-Bounds Read in read_image_tga

Using application provided parameters, in these cases invalid data
causes the issues :

  - Integer overflow error within _gdContributionsAlloc()
    (CVE-2016-6207)

  - fix php bug php#72494, invalid color index not handled,
    can lead to crash

  - improve color check for CropThreshold

Important update :

  - gdImageCopyResampled has been improved. Better handling
    of images with alpha channel, also brings libgd in sync
    with php's bundled gd.

This is a recommended update.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-615f3bf06e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gd package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^24([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 24", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC24", reference:"gd-2.2.3-1.fc24")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gd");
}
