#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-219.
#

include("compat.inc");

if (description)
{
  script_id(24305);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:54:55 $");

  script_cve_id("CVE-2007-0452");
  script_xref(name:"FEDORA", value:"2007-219");

  script_name(english:"Fedora Core 5 : samba-3.0.24-1.fc5 (2007-219)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Wed Feb 7 2007 Jay Fenlason <fenlason at redhat.com>
    3.0.24-1.fc5

    - New upstream release

    - Update the -man patch to work with 3.0.24

    - This release fixes CVE-2007-0452 Samba smbd denial of
      service

  - Tue Sep 26 2006 Jay Fenlason <fenlason at redhat.com>
    3.0.23c-1.fc5

    - Include the newer smb.init that includes the
      configtest option

    - Upgrade to 3.0.23c, obsoleting the -samr_alias patch.

    - Wed Aug 9 2006 Jay Fenlason <fenlason at redhat.com>
      3.0.23b-1.fc5

    - New upstream release, fixing some annoying bugs.

    - Mon Jul 24 2006 Jay Fenlason <fenlason at redhat.com>
      3.0.23a-1.fc5.1

    - Fix the -logfiles patch to close bz#199607 Samba
      compiled with wrong log path. bz#199206 smb.conf has
      incorrect log file path

  - Mon Jul 24 2006 Jay Fenlason <fenlason at redhat.com>
    3.0.23a-1.fc5

    - Upgrade to new upstream 3.0.23a

    - include upstream samr_alias patch

    - Wed Jul 12 2006 Jay Fenlason <fenlason at redhat.com>
      3.0.23-1.fc5

    - Upgrade to 3.0.23 to close bz#197836 CVE-2006-3403
      Samba denial of service

  - include related spec file, filter-requires-samba.sh and
    patch changes from rawhide.

  - include the fixed smb.init file from rawhide, closing
    bz#182560 Wrong retval for initscript when smbd is dead

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-February/001389.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b7a6a036"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:samba-swat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC5", reference:"samba-3.0.24-1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"samba-client-3.0.24-1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"samba-common-3.0.24-1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"samba-debuginfo-3.0.24-1.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"samba-swat-3.0.24-1.fc5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba / samba-client / samba-common / samba-debuginfo / samba-swat");
}
