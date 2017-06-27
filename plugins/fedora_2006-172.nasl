#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2006-172.
#

include("compat.inc");

if (description)
{
  script_id(21101);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/21 21:46:26 $");

  script_cve_id("CVE-2006-0745");
  script_xref(name:"FEDORA", value:"2006-172");

  script_name(english:"Fedora Core 5 : xorg-x11-server-1.0.1-9 (2006-172)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Coverity scanned the X.Org source code for problems and reported their
findings to the X.Org development team. Upon analysis, Alan
Coopersmith, a member of the X.Org development team, noticed a couple
of serious security issues in the findings. In particular, the Xorg
server can be exploited for root privilege escalation by passing a
path to malicious modules using the -modulepath command line argument.
Also, the Xorg server can be exploited to overwrite any root writable
file on the filesystem with the -logfile command line argument.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2006-March/001872.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?77e9aff9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-server-sdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 5.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC5", reference:"xorg-x11-server-Xdmx-1.0.1-9")) flag++;
if (rpm_check(release:"FC5", reference:"xorg-x11-server-Xnest-1.0.1-9")) flag++;
if (rpm_check(release:"FC5", reference:"xorg-x11-server-Xorg-1.0.1-9")) flag++;
if (rpm_check(release:"FC5", reference:"xorg-x11-server-Xvfb-1.0.1-9")) flag++;
if (rpm_check(release:"FC5", reference:"xorg-x11-server-debuginfo-1.0.1-9")) flag++;
if (rpm_check(release:"FC5", reference:"xorg-x11-server-sdk-1.0.1-9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-server-Xdmx / xorg-x11-server-Xnest / xorg-x11-server-Xorg / etc");
}
