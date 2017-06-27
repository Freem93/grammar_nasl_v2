#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-6723.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(66321);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/10/19 21:56:44 $");

  script_cve_id("CVE-2013-1917", "CVE-2013-1919", "CVE-2013-1964");
  script_bugtraq_id(59291, 59292, 59293);
  script_xref(name:"FEDORA", value:"2013-6723");

  script_name(english:"Fedora 17 : xen-4.1.5-1.fc17 (2013-6723)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Thu Apr 25 2013 Michael Young <m.a.young at
    durham.ac.uk> - 4.1.5-1

    - update to xen-4.1.5 includes fixes for passed through
      IRQs or PCI devices might allow denial of service
      attack [XSA-46, CVE-2013-1919] (#953568) SYSENTER in
      32-bit PV guests on 64-bit xen can crash hypervisor
      [XSA-44, CVE-2013-1917] (#953569) grant releases can
      release more than intended potentially crashing xen
      [XSA-50, CVE-2013-1964] (#953632)

  - remove patches that are included in 4.1.5

    - allow xendomains to work with xl saved images

    - Thu Apr 4 2013 Michael Young <m.a.young at
      durham.ac.uk> - 4.1.4-7

    - make xendomains systemd script executable (#919705)

    - Potential use of freed memory in event channel
      operations [XSA-47, CVE-2013-1920]

  - Fri Feb 22 2013 Michael Young <m.a.young at
    durham.ac.uk> - 4.1.4-6

    - patch for [XSA-36, CVE-2013-0153] can cause boot time
      crash

    - backport the fixes discovered when building with gcc
      4.8

    - Fri Feb 15 2013 Michael Young <m.a.young at
      durham.ac.uk> - 4.1.4-5

    - patch for [XSA-38, CVE-2013-0215] was flawed

    - Wed Feb 6 2013 Michael Young <m.a.young at
      durham.ac.uk> - 4.1.4-4

    - guest using oxenstored can crash host or exhaust
      memory [XSA-38, CVE-2013-0215] (#907888)

  - guest using AMD-Vi for PCI passthrough can cause denial
    of service [XSA-36, CVE-2013-0153] (#910914)

  - Thu Jan 17 2013 Michael Young <m.a.young at
    durham.ac.uk> - 4.1.4-3

    - Buffer overflow when processing large packets in qemu
      e1000 device driver [XSA-41, CVE-2012-6075] (#910845)

  - fix a bug introduced by fix for XSA-27

    - Fri Jan 11 2013 Michael Young <m.a.young at
      durham.ac.uk> - 4.1.4-2

    - VT-d interrupt remapping source validation flaw
      [XSA-33, CVE-2012-5634] (#893568)

  - Tue Dec 18 2012 Michael Young <m.a.young at
    durham.ac.uk> - 4.1.4-1

    - update to xen-4.1.4

    - remove patches that are included in 4.1.4

    - Tue Dec 4 2012 Michael Young <m.a.young at
      durham.ac.uk> - 4.1.3-7

    - 6 security fixes A guest can cause xen to crash
      [XSA-26, CVE-2012-5510] (#883082) An HVM guest can
      cause xen to run slowly or crash [XSA-27,
      CVE-2012-5511] (#883084) An HVM guest can cause xen to
      crash or leak information [XSA-28, CVE-2012-5512]
      (#883085) A PV guest can cause xen to crash and might
      be able escalate privileges [XSA-29, CVE-2012-5513]
      (#883088) An HVM guest can cause xen to hang [XSA-30,
      CVE-2012-5514] (#883091) A guest can cause xen to hang
      [XSA-31, CVE-2012-5515] (#883092)

  - Tue Nov 13 2012 Michael Young <m.a.young at
    durham.ac.uk> - 4.1.3-6

    - 5 security fixes A guest can block a cpu by setting a
      bad VCPU deadline [XSA 20, CVE-2012-4535] (#876198)

[plus 60 lines in the Changelog]

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=950668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=950686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=953632"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-May/104537.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?21e17665"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:17");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^17([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 17.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC17", reference:"xen-4.1.5-1.fc17")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
