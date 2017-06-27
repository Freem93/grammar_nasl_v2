#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-9550.
#

include("compat.inc");

if (description)
{
  script_id(35016);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 22:32:47 $");

  script_cve_id("CVE-2008-4690");
  script_bugtraq_id(15395);
  script_xref(name:"FEDORA", value:"2008-9550");

  script_name(english:"Fedora 9 : lynx-2.8.6-17.fc9 (2008-9550)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Mon Nov 10 2008 Jiri Moskovcak <jmoskovc at redhat.com>
    2.8.6-17

    - Fixed CVE-2008-4690 lynx: remote arbitrary command
      execution. via a crafted lynxcgi: URL (thoger)

  - Fri May 30 2008 Jiri Moskovcak <jmoskovc at redhat.com>
    2.8.6-16

    - updated to latest stable upstream version 2.8.6rel5

    - Fri May 23 2008 Dennis Gilmore <dennis at ausil.us> -
      2.8.6-15.1

    - minor rebuild on sparc

    - Sat May 17 2008 Dennis Gilmore <dennis at ausil.us> -
      2.8.6-15

    - even with the patches it still built wrong in koji.

    - limit -j to 24 for sparc

    - Thu May 8 2008 Dennis Gilmore <dennis at ausil.us> -
      2.8.6-14

    - patch from ajax to fix parallel builds

    - additional patch from me for parallel builds

    - set default home page to start.fedoraproject.org

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=468184"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/016976.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?baf14d3e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected lynx package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:lynx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 9.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC9", reference:"lynx-2.8.6-17.fc9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lynx");
}
