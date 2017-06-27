#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-4047180cd3.
#

include("compat.inc");

if (description)
{
  script_id(100188);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/16 13:59:27 $");

  script_cve_id("CVE-2017-5209", "CVE-2017-5545", "CVE-2017-5834", "CVE-2017-5835", "CVE-2017-5836", "CVE-2017-6435", "CVE-2017-6436", "CVE-2017-6437", "CVE-2017-6438", "CVE-2017-6439", "CVE-2017-6440");
  script_xref(name:"FEDORA", value:"2017-4047180cd3");

  script_name(english:"Fedora 25 : libplist (2017-4047180cd3)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Version 2.0.0

Changes :

  - New light-weight custom XML parser

  - Remove libxml2 dependency

  - Refactor binary plist parsing

  - Improved malformed XML and binary plist detection and
    error handling

  - Add parser debug/error output (when compiled with
    --enable-debug), controlled via environment variables

  - Fix unicode character handling

  - Add PLIST_IS_* helper macros for the different node
    types

  - Extend date/time range and date conversion issues

  - Add plist_is_binary() and plist_from_memory() functions
    to the interface

  - Plug several memory leaks

  - Speed improvements for handling large plist files

Includes security fixes for :

  - CVE-2017-6440

  - CVE-2017-6439

  - CVE-2017-6438

  - CVE-2017-6437

  - CVE-2017-6436

  - CVE-2017-6435

  - CVE-2017-5836

  - CVE-2017-5835

  - CVE-2017-5834

  - CVE-2017-5545

  - CVE-2017-5209

... and several others that didn't receive any CVE (yet).

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-4047180cd3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libplist package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libplist");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:25");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^25([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 25", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC25", reference:"libplist-2.0.0-1.fc25")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libplist");
}
