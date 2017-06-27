#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2006-966.
#

include("compat.inc");

if (description)
{
  script_id(24177);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:46:28 $");

  script_xref(name:"FEDORA", value:"2006-966");

  script_name(english:"Fedora Core 5 : bind-9.3.2-33.fc5 (2006-966)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Mon Sep 11 2006 Martin Stransky <stransky at redhat.com>
    - 30:9.3.2-33

    - added fix for CVE-2006-4095

    - added bind to PreReq (#202542)

    - Fri Jul 21 2006 Jason Vas Dias <jvdias at redhat.com>
      - 30:9.3.2-32

    - fix addenda to bug 189789: determination of selinux
      enabled was still not 100% correct in
      bind-chroot-admin

  - fix addenda to bug 196398: make named.init test for
    NetworkManager being enabled AFTER testing for -D
    absence; named.init now supports a 'DISABLE_NAMED_DBUS'
    /etc/sysconfig/named setting to disable auto-enable of
    named dbus support if NetworkManager enabled.

  - Wed Jul 19 2006 Jason Vas Dias <jvdias at redhat.com> -
    30:9.3.2-30

    - fix bug 196398 - Enable -D option automatically in
      initscript if NetworkManager enabled in any runlevel.

  - fix bugs 191093, 189789

    - fix bug 196962 (fixed by backported 9.3.3b1 fixes to
      lib/isc/unix/ifiter_ioctl.c)

    - backport selected fixes from upstream bind9 'v9_3_3b1'
      CVS version: ( see http://www.isc.org/sw/bind9.3.php
      'Fixes' ): o change 2024 / bug 16027: named emitted
      spurious 'zone serial unchanged' messages on reload o
      change 2013 / bug 15941: handle unexpected TSIGs on
      unsigned AXFR/IXFR responses more gracefully o change
      2009 / bug 15808: coverity fixes o change 1997 / bug
      15818: named was failing to replace negative cache
      entries when a positive one for the type was learnt o
      change 1994 / bug 15694: OpenSSL 0.9.8 support o
      change 1991 / bug 15813: The configuration data, once
      read, should be treated as readonly. o misc. validator
      fixes o misc. resolver fixes o misc. dns fixes o misc.
      isc fixes o misc. libbind fixes o misc. isccfg fix o
      misc. lwres fix o misc. named fixes o misc. dig fixes
      o misc. nsupdate fix o misc. tests fixes

  - Wed Jun 7 2006 Jeremy Katz <katzj at redhat.com> -
    30:9.3.2-24.FC6

    - and actually put the devel symlinks in the right
      subpackage

    - Thu May 25 2006 Jeremy Katz <katzj at redhat.com> -
      30:9.3.2-23.FC6

    - rebuild for -devel deps

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.isc.org/sw/bind9.3.php"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2006-September/000598.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d12a9d2a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bind-libbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:caching-nameserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/11");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 5.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC5", reference:"bind-9.3.2-33.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"bind-chroot-9.3.2-33.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"bind-debuginfo-9.3.2-33.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"bind-devel-9.3.2-33.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"bind-libbind-devel-9.3.2-33.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"bind-libs-9.3.2-33.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"bind-sdb-9.3.2-33.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"bind-utils-9.3.2-33.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"caching-nameserver-9.3.2-33.fc5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-debuginfo / bind-devel / etc");
}
