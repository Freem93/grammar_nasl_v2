#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-12293.
#

include("compat.inc");

if (description)
{
  script_id(62135);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/20 22:25:12 $");

  script_cve_id("CVE-2012-3403", "CVE-2012-3481");
  script_xref(name:"FEDORA", value:"2012-12293");

  script_name(english:"Fedora 18 : gimp-2.8.2-1.fc18 (2012-12293)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Among other things this update fixes security and stability issues in
various image format loaders. Security issues fixed include
CVE-2012-3403 and CVE-2012-3481.

Overview of Changes from GIMP 2.8.0 to GIMP 2.8.2
=================================================

Core :

  - Make tag matching always case-insensitive

    - Let the tile-cache-size default to half the physical
      memory

GUI :

  - Mention that the image was exported in the close warning
    dialog

    - Make sure popup windows appear on top on OSX

    - Allow file opening by dropping to the OSX dock

    - Fix the visibility logic of the export/overwrite menu
      items

    - Remove all 'Use GEGL' menu items, they only add bugs
      and zero function

    - Improve performance of display filters, especially
      color management

    - Fix the image window title to comply with the
      save/export spec and use the same image name
      everywhere, not only in the title

  - Fix positioning of pasted/dropped stuff to be more
    reasonable

Libgimp :

  - Move gimpdir and thumbnails to proper locations on OSX

    - Implement relocation on OSX

    - Allow to use $(gimp_installation_dir) in config files

Plug-ins :

  - Fix remembering of JPEG load/save defaults

    - Revive the page setup dialog on Windows

Source and build system :

  - Add Windows installer infrastructure

    - Add infrastructure to build GIMP.app on OSX

General :

  - Lots of bug fixes

    - List of translation updates

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=839020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=847303"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-September/086964.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2c849e84"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gimp package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gimp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/18");
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
if (! ereg(pattern:"^18([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 18.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC18", reference:"gimp-2.8.2-1.fc18")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gimp");
}
