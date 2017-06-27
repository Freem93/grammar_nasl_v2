#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-4604.
#

include("compat.inc");

if (description)
{
  script_id(32467);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 22:23:15 $");

  script_cve_id("CVE-2007-1320");
  script_bugtraq_id(23731);
  script_xref(name:"FEDORA", value:"2008-4604");

  script_name(english:"Fedora 8 : kvm-60-6.fc8 (2008-4604)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Tue May 27 2008 Glauber Costa <gcosta at redhat.com> -
    60-6.fc8

    - Fix Cirrus heap overflow vulnerability (#448524)

    - Fri May 23 2008 Daniel P. Berrange <berrange at
      redhat.com> - 60-5.fc8

    - Put PTY in rawmode

    - Fri May 16 2008 Glauber Costa <gcosta at redhat.com> -
      60-4.fc8

    - Fix problem with cirrus device that was breaking vnc
      connections (rhbz #446830)

    - Wed Feb 27 2008 Daniel P. Berrange <berrange at
      redhat.com> - 60-3.fc8

    - Fix block device checks for extendable disk formats
      (rhbz #434978)

    - Sat Feb 23 2008 Daniel P. Berrange <berrange at
      redhat.com> - 60-2.fc8

    - Fix block device extents check (rhbz #433560)

    - Thu Jan 31 2008 Jeremy Katz <katzj at redhat.com>

    - We don't need e2fsprogs-devel to build anymore
      (#331871)

    - Thu Jan 24 2008 Daniel P. Berrange <berrange at
      redhat.com> - 60-1.fc9

    - Updated to kvm-60

    - Fix license tag to keep rpmlint quiet

    - Remove unused PPC, Sparc and PPC Video BIOS

    - Tue Jan 15 2008 Bill Nottingham <notting at
      redhat.com>: - 59-1

    - add upstream patch to fix VMs that no longer boot
      (#427317)

    - update to kvm-59

    - Thu Dec 27 2007 Jeremy Katz <katzj at redhat.com> -
      58-2

    - Fix up defaults patch to apply

    - Thu Dec 27 2007 Jeremy Katz <katzj at redhat.com> -
      58-1

    - Update to kvm-58

    - Thu Dec 13 2007 Jeremy Katz <katzj at redhat.com> -
      56-1

    - Update to kvm-56

    - Tue Dec 4 2007 Jeremy Katz <katzj at redhat.com> -
      55-1

    - Update to kvm-55

    - Mon Dec 3 2007 Jeremy Katz <katzj at redhat.com> -
      54-1

    - update to kvm-54

    - Tue Nov 20 2007 Jeremy Katz <katzj at redhat.com> -
      53-1

    - update to kvm-53

    - Wed Nov 7 2007 Jeremy Katz <katzj at redhat.com> -
      51-1

    - update to kvm-51

    - Tue Nov 6 2007 Jeremy Katz <katzj at redhat.com> -
      50-1

    - update to kvm-50, drop all the patches that have gone
      upstream

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=237342"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-May/010587.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d676bebd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected kvm package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kvm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/29");
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
if (! ereg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 8.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC8", reference:"kvm-60-6.fc8")) flag++;


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
