#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-20125.
#

include("compat.inc");

if (description)
{
  script_id(63491);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/09 15:27:59 $");

  script_bugtraq_id(55867, 56684);
  script_xref(name:"FEDORA", value:"2012-20125");

  script_name(english:"Fedora 18 : webkitgtk-1.10.2-1.fc18 / webkitgtk3-1.10.2-1.fc18 (2012-20125)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"What's new in WebKitGTK+ 1.10.2? ================================

  - WebCore has been split in a few more convenience libtool
    libraries, which should fix problems with linking in
    some architectures and with make's command line length
    limit.

    - WebKit2 introspection files will also be built if
      introspection is enabled.

    - Includes fixes for the following CVEs: CVE-2012-5112,
      CVE-2012-5133

  - Web audio has been fixed to use a GstBuffer per-channel
    when looping, which sidesteps a race when dealing with
    the object references. It also got improvements to error
    handling and ease of testing when loading resources.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-January/095647.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?03fa765e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-January/095648.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d0cb4bde"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected webkitgtk and / or webkitgtk3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:webkitgtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:webkitgtk3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC18", reference:"webkitgtk-1.10.2-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"webkitgtk3-1.10.2-1.fc18")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "webkitgtk / webkitgtk3");
}
