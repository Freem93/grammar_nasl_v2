#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-281.
#

include("compat.inc");

if (description)
{
  script_id(24716);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/08 20:11:35 $");

  script_cve_id("CVE-2006-6077", "CVE-2007-0008", "CVE-2007-0775", "CVE-2007-0776", "CVE-2007-0777", "CVE-2007-0778", "CVE-2007-0779", "CVE-2007-0780", "CVE-2007-0800", "CVE-2007-0981", "CVE-2007-0995", "CVE-2007-0996");
  script_xref(name:"FEDORA", value:"2007-281");

  script_name(english:"Fedora Core 5 : firefox-1.5.0.10-1.fc5 (2007-281)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Thu Feb 22 2007 Martin Stransky <stransky at redhat.com>
    - 1.5.0.10-1

    - Update to 1.5.0.10

    - Wed Dec 20 2006 Christopher Aillon <caillon at
      redhat.com> - 1.5.0.9-1

    - Update to 1.5.0.9

    - Tue Nov 7 2006 Christopher Aillon <caillon at
      redhat.com> - 1.5.0.8-1

    - Update to 1.5.0.8

    - Fix up a few items in the download manager

    - Use the bullet character for password fields.

    - Add pango printing patch from Behdad.

    - Wed Sep 13 2006 Christopher Aillon <caillon at
      redhat.com> - 1.5.0.7-1

    - Update to 1.5.0.7

    - Bring in pango patches from rawhide to fix MathML and
      cursor positioning

    - Tue Aug 8 2006 Jesse Keating <jkeating at redhat.com>
      - 1.5.0.6-2

    - Use dist tag

    - rebuild

    - Thu Aug 3 2006 Kai Engert <kengert at redhat.com> -
      1.5.0.6-1.1.fc5

    - Update to 1.5.0.6

    - Thu Jul 27 2006 Christopher Aillon <caillon at
      redhat.com> - 1.5.0.5-1.1.fc5

    - Update to 1.5.0.5

    - Wed Jun 14 2006 Kai Engert <kengert at redhat.com> -
      1.5.0.4-1.2.fc5

    - Force 'gmake -j1' on ppc ppc64 s390 s390x

    - Mon Jun 12 2006 Kai Engert <kengert at redhat.com> -
      1.5.0.4-1.1.fc5

    - Firefox 1.5.0.4

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-February/001503.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?154d3fe6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox and / or firefox-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(79, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/27");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 5.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC5", reference:"firefox-1.5.0.10-1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"firefox-debuginfo-1.5.0.10-1.fc5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / firefox-debuginfo");
}
