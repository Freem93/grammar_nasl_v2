#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-22771.
#

include("compat.inc");

if (description)
{
  script_id(71475);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/19 21:47:14 $");

  script_cve_id("CVE-2013-1913", "CVE-2013-1978");
  script_xref(name:"FEDORA", value:"2013-22771");

  script_name(english:"Fedora 18 : gimp-2.8.10-4.fc18 (2013-22771)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Overview of Changes from GIMP 2.8.8 to GIMP 2.8.10
==================================================

GUI :

  - Indicate if a file was exported in the Quit dialog

    - Add shortcuts and hint labels to the close and quit
      dialogs that make closing and quitting easier and more
      consistent

  - Rename the File->Export menu labels to match Save/Save
    as

    - Fix keyboard shortcuts on OSX Mavericks

    - Don't open lots of progress popups when opening many
      files

    - Correctly restore the hidden state of docks in single
      window mode

Libgimp :

  - Fix exporting an image consisting of a single layer
    group

    - Don't attempt to pick transparent colors

Plug-ins :

  - Fix crash in LCMS plugin if RGB profile was missing

General :

  - Bug fixes

    - Translation updates Overview of Changes from GIMP
      2.8.8 to GIMP 2.8.10
      ==================================================

GUI :

  - Indicate if a file was exported in the Quit dialog

    - Add shortcuts and hint labels to the close and quit
      dialogs that make closing and quitting easier and more
      consistent

  - Rename the File->Export menu labels to match Save/Save
    as

    - Fix keyboard shortcuts on OSX Mavericks

    - Don't open lots of progress popups when opening many
      files

    - Correctly restore the hidden state of docks in single
      window mode

Libgimp :

  - Fix exporting an image consisting of a single layer
    group

    - Don't attempt to pick transparent colors

Plug-ins :

  - Fix crash in LCMS plugin if RGB profile was missing

General :

  - Bug fixes

    - Translation updates

Additionally, this update fixes buffer overflows in the XWD loader.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1037720"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-December/124160.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d0f61aa4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gimp package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gimp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/17");
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
if (! ereg(pattern:"^18([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 18.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC18", reference:"gimp-2.8.10-4.fc18")) flag++;


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
