#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2016-d132dbb529.
#

include("compat.inc");

if (description)
{
  script_id(89619);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/03/04 16:19:57 $");

  script_xref(name:"FEDORA", value:"2016-d132dbb529");

  script_name(english:"Fedora 22 : webkitgtk4-2.10.4-1.fc22 (2016-d132dbb529)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to 2.10.4. Major new features: * New HTTP disk cache for the
Network Process. * IndexedDB support. * New Web Inspector UI. *
Automatic ScreenServer inhibition when playing fullscreen videos. *
Initial Editor API.

  - Performance improvements. This update addresses the
    following vulnerabilities: * CVE-2015-1122 *
    CVE-2015-1152 * CVE-2015-1155 * CVE-2015-3660 *
    CVE-2015-3730 * CVE-2015-3738 * CVE-2015-3740 *
    CVE-2015-3742 * CVE-2015-3744 * CVE-2015-3746 *
    CVE-2015-3750 * CVE-2015-3751 * CVE-2015-3754 *
    CVE-2015-3755 * CVE-2015-5804 * CVE-2015-5805 *
    CVE-2015-5807 * CVE-2015-5810 * CVE-2015-5813 *
    CVE-2015-5814 * CVE-2015-5815 * CVE-2015-5817 *
    CVE-2015-5818 * CVE-2015-5825 * CVE-2015-5827 *
    CVE-2015-5828 * CVE-2015-5929 * CVE-2015-5930 *
    CVE-2015-5931 * CVE-2015-7002 * CVE-2015-7013 *
    CVE-2015-7014 * CVE-2015-7048 * CVE-2015-7095 *
    CVE-2015-7097 * CVE-2015-7099 * CVE-2015-7100 *
    CVE-2015-7102 * CVE-2015-7103 * CVE-2015-7104 For
    further information on the new features, see the [Igalia
    blog
    post](http://blogs.igalia.com/carlosgc/2015/09/21/webkit
    gtk-2-10/). For information on the security
    vulnerabilities, refer to [WebKitGTK+ Security Advisory
    WSA-2015-0002](http://webkitgtk.org/security/WSA-2015-00
    02.html).

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://blogs.igalia.com/carlosgc/2015/09/21/webkitgtk-2-10/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://webkitgtk.org/security/WSA-2015-0002.html"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-February/176536.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e5712c42"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected webkitgtk4 package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:webkitgtk4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");
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
if (! ereg(pattern:"^22([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 22.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC22", reference:"webkitgtk4-2.10.4-1.fc22")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "webkitgtk4");
}
