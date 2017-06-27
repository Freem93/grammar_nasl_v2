#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-11705.
#

include("compat.inc");

if (description)
{
  script_id(35266);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/08 20:11:36 $");

  script_cve_id("CVE-2007-1320", "CVE-2008-2382", "CVE-2008-4539");
  script_bugtraq_id(23731, 32910);
  script_xref(name:"FEDORA", value:"2008-11705");

  script_name(english:"Fedora 9 : kvm-65-15.fc9 (2008-11705)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"----------------------------------------------------------------------
---------- ChangeLog :

  - Mon Dec 22 2008 Glauber Costa <gcosta at redhat.com> -
    65-15.fc9

    - Fixed CVE-2008-2382.

    - Thu Dec 4 2008 Glauber Costa <gcosta at redhat.com> -
      65-14.fc9

    - Fixed bug that corrupted gnome-panel #474702

    - Tue Dec 2 2008 Glauber Costa <gcosta at redhat.com> -
      65-12.fc9

    - Properly set flags for interrupt return #464304

    - Tue Nov 11 2008 Glauber Costa <gcosta at redhat.com> -
      65-11.fc9

    - Fix CVE-2008-4539 #448525

    - Mon Oct 13 2008 Glauber Costa <gcosta at redhat.com> -
      65-10.fc9

    - Fix sysenter save in 64-bit hosts #457649

    - Thu Aug 28 2008 Glauber Costa <gcosta at redhat.com> -
      65-9.fc9

    - there's already a 65-8 tag

    - Thu Aug 28 2008 Glauber Costa <gcosta at redhat.com> -
      65-8.fc9

    - Fixes #459778

    - Fixes #452355

    - Tue May 27 2008 Glauber Costa <gcosta at redhat.com> -
      65-7.fc9

    - Fix the build

    - Tue May 27 2008 Glauber Costa <gcosta at redhat.com> -
      65-6.fc9

    - Fix Cirrus heap overflow vulnerability (#448525)

    - Fri May 23 2008 Daniel P. Berrange <berrange at
      redhat.com> - 65-5.fc9

    - Put PTY in rawmode

    - Tue May 20 2008 Mark McLoughlin <markmc at redhat.com>
      - 65-4.fc9

    - Re-enable patch to fix -kernel with virtio/extboot
      drives (#444578)

    - Fri May 16 2008 Glauber Costa <gcosta at redhat.com> -
      65-3.fc9

    - Fix problem with cirrus device that was breaking vnc
      connections (rhbz #446830)

    - Tue Apr 29 2008 Mark McLoughlin <markmc at redhat.com>
      - 65-2

    - Fix -kernel with virtio/extboot drives (#444578)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=466890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=477636"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/018133.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64d81e1d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/018175.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8db883e7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected kvm package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kvm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC9", reference:"kvm-65-15.fc9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kvm");
}
