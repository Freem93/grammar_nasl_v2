#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-2664.
#

include("compat.inc");

if (description)
{
  script_id(27786);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/08 20:11:35 $");

  script_cve_id("CVE-2006-2894", "CVE-2007-1095", "CVE-2007-2292", "CVE-2007-3511", "CVE-2007-5334", "CVE-2007-5335", "CVE-2007-5337", "CVE-2007-5338", "CVE-2007-5339", "CVE-2007-5340");
  script_bugtraq_id(22688, 23668, 24725, 25543, 26132);
  script_xref(name:"FEDORA", value:"2007-2664");

  script_name(english:"Fedora 7 : firefox-2.0.0.8-1.fc7 (2007-2664)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fri Oct 19 2007 Christopher Aillon <caillon at
    redhat.com> - 2.0.0.8-1

    - Update to 2.0.0.8

    - Tue Oct 16 2007 Martin Stransky <stransky at
      redhat.com>

    - added fix for #246248 - firefox crashes when searching

    - Wed Jul 18 2007 Kai Engert <kengert at redhat.com> -
      2.0.0.5-1

    - Update to 2.0.0.5

    - Fri Jun 29 2007 Martin Stransky <stransky at
      redhat.com> 2.0.0.4-3

    - backported pango patches from FC6 (1.5.0.12)

    - Sun Jun 3 2007 Christopher Aillon <caillon at
      redhat.com> 2.0.0.4-2

    - Properly clean up threads with newer NSPR

    - Wed May 30 2007 Christopher Aillon <caillon at
      redhat.com> 2.0.0.4-1

    - Final version

    - Wed May 23 2007 Christopher Aillon <caillon at
      redhat.com> 2.0.0.4-0.rc3

    - Update to 2.0.0.4 RC3

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-October/004325.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?126667bf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected firefox, firefox-debuginfo and / or firefox-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 20, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"firefox-2.0.0.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"firefox-debuginfo-2.0.0.8-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"firefox-devel-2.0.0.8-1.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / firefox-debuginfo / firefox-devel");
}
