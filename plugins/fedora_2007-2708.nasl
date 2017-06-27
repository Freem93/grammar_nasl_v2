#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-2708.
#

include("compat.inc");

if (description)
{
  script_id(27794);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/08 20:11:35 $");

  script_cve_id("CVE-2007-1321", "CVE-2007-3919", "CVE-2007-4993");
  script_xref(name:"FEDORA", value:"2007-2708");

  script_name(english:"Fedora 7 : xen-3.1.0-8.fc7 (2007-2708)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fri Oct 26 2007 Daniel P. Berrange <berrange at
    redhat.com> - 3.1.0-8.fc7

    - Fixed xenbaked tmpfile flaw (CVE-2007-3919)

    - Wed Sep 26 2007 Daniel P. Berrange <berrange at
      redhat.com> - 3.1.0-7.fc7

    - Fixed rtl8139 checksum calculation for Vista (rhbz
      #308201)

    - Wed Sep 26 2007 Chris Lalancette <clalance at
      redhat.com> - 3.1.0-6.fc7

    - QEmu NE2000 overflow check - CVE-2007-1321

    - Pygrub guest escape - CVE-2007-4993

    - Mon Sep 24 2007 Daniel P. Berrange <berrange at
      redhat.com> - 3.1.0-5.fc7

    - Fix generation of manual pages (rhbz #250791)

    - Fix 32-on-64 PVFB for FC6 legacy guests

    - Mon Sep 24 2007 Daniel P. Berrange <berrange at
      redhat.com> - 3.1.0-4.fc7

    - Fix VMX assist IRQ handling (rhbz #279581)

    - Sun Sep 23 2007 Daniel P. Berrange <berrange at
      redhat.com> - 3.1.0-3.fc7

    - Don't clobber the VIF type attribute in FV guests
      (rhbz #247122)

    - Wed Aug 1 2007 Markus Armbruster <armbru at
      redhat.com>

    - Put guest's native protocol ABI into xenstore, to
      provide for older kernels running 32-on-64.

  - VNC keymap fixes

    - Fix race conditions in LibVNCServer on client
      disconnect

    - Mon Jun 11 2007 Daniel P. Berrange <berrange at
      redhat.com> - 3.1.0-2.fc7

    - Remove patch which kills VNC monitor

    - Fix HVM save/restore file path to be /var/lib/xen
      instead of /tmp

    - Don't spawn a bogus xen-vncfb daemon for HVM guests

    - Fri May 25 2007 Daniel P. Berrange <berrange at
      redhat.com> - 3.1.0-1.fc7

    - Updated to official 3.1.0 tar.gz

    - Fixed data corruption from VNC client disconnect (bz
      241303)

    - Thu May 17 2007 Daniel P. Berrange <berrange at
      redhat.com> - 3.1.0-0.rc7.2.fc7

    - Ensure xen-vncfb processes are cleanedup if guest
      quits (bz 240406)

    - Tear down guest if device hotplug fails

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=350421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=361981"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004408.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4fe30cec"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 59, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xen-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/01");
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
if (rpm_check(release:"FC7", reference:"xen-3.1.0-8.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xen-debuginfo-3.1.0-8.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xen-devel-3.1.0-8.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xen-libs-3.1.0-8.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-debuginfo / xen-devel / xen-libs");
}
