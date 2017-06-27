#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2006-808.
#

include("compat.inc");

if (description)
{
  script_id(24149);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:46:27 $");

  script_xref(name:"FEDORA", value:"2006-808");

  script_name(english:"Fedora Core 4 : samba-3.0.23-1.fc4 (2006-808)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Wed Jul 12 2006 Jay Fenlason <fenlason at redhat.com>
    3.0.23-1.fc4

    - Update to 3.0.23 to close bz#197836 CVE-2006-3403
      Samba denial of service

  - include related spec file, filter-requires-samba.sh and
    patch changes from rawhide. -winbind, and -access
    patches are obsolete.

  - include the fixed smb.init file from rawhide, closing
    bz#182560 Wrong retval for initscript when smbd is dead

  - Mon Oct 10 2005 Jay Fenlason <fenlason at redhat.com>

    - Upgrade to 3.0.20a, which includes all the previous
      upstream patches.

    - Include the -winbind patch from Jeremy Allison <jra at
      samba.org> to fix a problem with winbind crashing.

  - Include the -access patch from Jeremy Allison <jra at
    samba.org> to fix a problem with MS Access lock files.

  - Updated the -warnings patch for 3.0.20a.

    - Include --with-shared-modules=idmap_ad,idmap_rid to
      close bz#156810 ?
      --with-shared-modules=idmap_ad,idmap_rid

  - Include the new samba.pamd from Tomas Mraz (tmraz at
    redhat.com) to close bz#170259 ? pam_stack is deprecated

  - Mon Aug 22 2005 Jay Fenlason <fenlason at redhat.com>

    - New upstream release Includes five upstream patches
      -bug3010_v1, -groupname_enumeration_v3,
      -regcreatekey_winxp_v1, -usrmgr_groups_v1, and
      -winbindd_v1 This obsoletes the -pie and -delim
      patches the -warning and -gcc4 patches are obsolete
      too The -man, -passwd, and -smbspool patches were
      updated to match 3.0.20pre1 Also, the -quoting patch
      was implemented differently upstream There is now a
      umount.cifs executable and manpage We run autogen.sh
      as part of the build phase The testprns command is now
      gone libsmbclient now has a man page

  - Include -bug106483 patch to close bz#106483 smbclient:
    -N negates the provided password, despite documentation

  - Added the -warnings patch to quiet some compiler
    warnings.

    - Removed many obsolete patches from CVS.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2006-July/000409.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6b23e045"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:samba-swat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/17");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 4.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC4", reference:"samba-3.0.23-1.fc4")) flag++;
if (rpm_check(release:"FC4", reference:"samba-client-3.0.23-1.fc4")) flag++;
if (rpm_check(release:"FC4", reference:"samba-common-3.0.23-1.fc4")) flag++;
if (rpm_check(release:"FC4", reference:"samba-debuginfo-3.0.23-1.fc4")) flag++;
if (rpm_check(release:"FC4", reference:"samba-swat-3.0.23-1.fc4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba / samba-client / samba-common / samba-debuginfo / samba-swat");
}
