#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-18731.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63048);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/20 22:34:53 $");

  script_bugtraq_id(56611, 56612, 56613, 56614, 56616, 56618, 56621, 56627, 56628, 56629, 56630, 56631, 56632, 56633, 56634, 56635, 56636, 56637, 56638, 56639, 56640, 56641, 56642, 56643, 56644);
  script_xref(name:"FEDORA", value:"2012-18731");

  script_name(english:"Fedora 18 : firefox-17.0-1.fc18 / thunderbird-17.0-1.fc18 / thunderbird-enigmail-1.4.6-2.fc18 / etc (2012-18731)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - First revision of the Social API and support for
    Facebook Messenger

    - Click-to-play blocklisting implemented to prevent
      vulnerable plugin versions from running without the
      user's permission (see blog post)

    - Updated Awesome Bar experience with larger icons

    - JavaScript Maps and Sets are now iterable

    - SVG FillPaint and StrokePaint implemented

    - Improvements that make the Web Console, Debugger and
      Developer Toolbar faster and easier to use

    - New Markup panel in the Page Inspector allows easy
      editing of the DOM

    - Sandbox attribute for iframes implemented, enabling
      increased security

    - Over twenty performance improvements, including fixes
      around the New Tab page

    - Pointer lock doesn't work in web apps (769150)

    - Page scrolling on sites with fixed headers (780345)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-November/092726.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?304d018c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-November/092727.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f188861d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-November/092728.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5266a7f2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-November/092729.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?87a6d069"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-November/092730.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?678dd25b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird-enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird-lightning");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/26");
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
if (rpm_check(release:"FC18", reference:"firefox-17.0-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"thunderbird-17.0-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"thunderbird-enigmail-1.4.6-2.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"thunderbird-lightning-1.9-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"xulrunner-17.0-3.fc18")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / thunderbird / thunderbird-enigmail / etc");
}
