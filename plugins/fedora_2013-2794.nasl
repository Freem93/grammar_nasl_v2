#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-2794.
#

include("compat.inc");

if (description)
{
  script_id(64858);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/19 21:47:15 $");

  script_bugtraq_id(58034, 58036, 58037, 58038, 58040, 58041, 58042, 58043, 58044, 58047, 58048, 58049, 58050, 58051);
  script_xref(name:"FEDORA", value:"2013-2794");

  script_name(english:"Fedora 18 : firefox-19.0-1.fc18 / thunderbird-17.0.3-1.fc18 / xulrunner-19.0-1.fc18 (2013-2794)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Built-in PDF viewer

    - Canvas elements can export their content as an image
      blob using canvas.toBlob()

    - Startup performance improvements (bugs 715402 and
      756313)

    - Debugger now supports pausing on exceptions and hiding
      non-enumerable properties

    - Remote Web Console is available for connecting to
      Firefox on Android or Firefox OS (experimental, set
      devtools.debugger.remote-enabled to true)

    - There is now a Browser Debugger available for add-on
      and browser developers (experimental, set
      devtools.chrome.enabled to true)

    - Web Console CSS links now open in the Style Editor

    - CSS @page is now supported

    - HTML5 CSS viewport-percentage length units implemented
      (vh, vw, vmin and vmax)

    - CSS text-transform now supports full-width Fixed :

  - Certain valid WebGL drawing operations are incorrectly
    rejected, leaving incomplete rendering in affected pages
    (825205)

    - Starting Firefox with -private flag incorrectly claims
      you are not in Private Browsing mode (802274)

    - Plugins stop rendering when the top half of the plugin
      is scrolled off the top of the page, in HiDPI mode
      (825734)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-February/099119.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f44ac90b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-February/099120.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2cde167c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-February/099121.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e3563b0d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox, thunderbird and / or xulrunner packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/24");
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
if (rpm_check(release:"FC18", reference:"firefox-19.0-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"thunderbird-17.0.3-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"xulrunner-19.0-1.fc18")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / thunderbird / xulrunner");
}
