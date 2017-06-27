#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-4709.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(29768);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 22:04:02 $");

  script_cve_id("CVE-2007-6285");
  script_bugtraq_id(26970);
  script_xref(name:"FEDORA", value:"2007-4709");

  script_name(english:"Fedora 7 : autofs-5.0.1-31 (2007-4709)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fri Dec 21 2007 Ian Kent <ikent at redhat.com> -
    5.0.1-31

    - Bug 426399: CVE-2007-6285 autofs default doesn't set
      nodev in /net [f7]

    - use mount option 'nodev' for '-hosts' map unless 'dev'
      is explicily specified.

    - Tue Dec 18 2007 Ian Kent <ikent at redhat.com> -
      5.0.1-30

    - Bug 397591 SELinux is preventing /sbin/rpc.statd
      (rpcd_t) 'search' to <Unknown> (sysctl_fs_t).

    - prevent fork between fd open and setting of
      FD_CLOEXEC.

    - Thu Dec 13 2007 Ian Kent <ikent at redhat.com> -
      5.0.1-29

    - Bug 421351: CVE-2007-5964 autofs defaults don't
      restrict suid in /net [f7]

    - use mount option 'nosuid' for '-hosts' map unless
      'suid' is explicily specified.

    - Wed Sep 5 2007 Ian Kent <ikent at redhat.com> -
      5.0.1-28

    - add ldaps support (required by schema discovery).

    - add back LDAP schema discovery if no schema is
      configured.

    - Tue Aug 28 2007 Ian Kent <ikent at redhat.com> -
      5.0.1-26

    - fix 'nosymlink' option handling and add desription to
      man page.

    - update patch to prevent failure on empty master map.

    - if there's no 'automount' entry in nsswitch.conf use
      'files' source.

    - add LDAP schema discovery if no schema is configured.

    - Tue Aug 21 2007 Ian Kent <ikent at redhat.com> -
      5.0.1-25

    - change random multiple server selection option name to
      be consistent with upstream naming.

  - Tue Aug 21 2007 Ian Kent <ikent at redhat.com> -
    5.0.1-24

    - don't fail on empty master map.

    - allow for older schemas that allow '*' as a key value.

    - add support for the '%' hack for case insensitive
      attribute schemas.

    - Mon Jul 30 2007 Ian Kent <ikent at redhat.com> -
      5.0.1-23

    - mark map instances stale so they aren't 'cleaned'
      during updates.

    - fix large file compile time option.

    - Fri Jul 27 2007 Ian Kent <ikent at redhat.com> -
      5.0.1-22

    - fix version passed to get_supported_ver_and_cost (bz
      249574).

    - Tue Jul 24 2007 Ian Kent <ikent at redhat.com> -
      5.0.1-21

    - fix parse confusion between attribute and attribute
      value.

    - Fri Jul 20 2007 Ian Kent <ikent at redhat.com> -
      5.0.1-20

    - fix handling of quoted slash alone (bz 248943).

    - Wed Jul 18 2007 Ian Kent <ikent at redhat.com> -
      5.0.1-19

    - fix wait time resolution in alarm and state queue
      handlers (bz 247711).

    - Mon Jul 16 2007 Ian Kent <ikent at redhat.com> -
      5.0.1-18

    - correct man page of patch which added mount options
      append control.

    - Mon Jul 16 2007 Ian Kent <ikent at redhat.com> -
      5.0.1-17

    - fix mount point directory creation for bind mounts.

    - add quoting for exports gathered by hosts map.

    - Thu Jun 7 2007 Ian Kent <ikent at redhat.com> -
      5.0.1-13

    - fix deadlock in alarm manager module.

    - Sun Jun 3 2007 Ian Kent <ikent at redhat.com> -
      5.0.1-11

    - correct mistake in logic test in wildcard lookup.

    - Mon May 7 2007 Ian Kent <ikent at redhat.com> -
      5.0.1-10

    - fix master map lexer to admit '.' in macro values.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=426399"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/006194.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd21c796"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected autofs and / or autofs-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:autofs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:autofs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/24");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"autofs-5.0.1-31")) flag++;
if (rpm_check(release:"FC7", reference:"autofs-debuginfo-5.0.1-31")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "autofs / autofs-debuginfo");
}
