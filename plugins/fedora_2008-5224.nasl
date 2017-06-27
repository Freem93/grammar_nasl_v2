#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-5224.
#

include("compat.inc");

if (description)
{
  script_id(33148);
  script_version ("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/12/08 20:21:53 $");

  script_cve_id("CVE-2008-0960", "CVE-2008-2292");
  script_bugtraq_id(29212, 29623);
  script_xref(name:"FEDORA", value:"2008-5224");

  script_name(english:"Fedora 7 : net-snmp-5.4-18.fc7 (2008-5224)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Tue Jun 10 2008 Jan Safranek <jsafranek at redhat.com>
    5.4-18

    - fix various flaws (CVE-2008-2292 CVE-2008-0960)

    - Thu Feb 14 2008 Jan Safranek <jsafranek at redhat.com>
      5.4-17

    - fixing ipNetToMediaNetAddress to show IP address
      (#432780)

    - Fri Oct 19 2007 Jan Safranek <jsafranek at redhat.com>
      5.4-16

    - License: field fixed to 'BSD and CMU'

    - fix hrSWInst (#250237)

    - fix leak in UDP transport (#247771)

    - fix remote DoS attack (CVE-2007-5846)

    - Mon Oct 8 2007 Jan Safranek <jsafranek at redhat.com>
      5.4-15

    - License: field changed to MIT

    - fix segfault on parsing smuxpeer without password
      (#316621)

    - Thu Jun 28 2007 Jan Safranek <jsafranek at redhat.com>
      5.4-14

    - fix snmptrapd hostname logging (#238587)

    - fix udpEndpointProcess remote IP address (#236551)

    - fix -M option of net-snmp-utils (#244784)

    - default snmptrapd.conf added (#243536)

    - fix crash when multiple exec statements have the same
      name (#243536)

  - fix ugly error message when more interfaces share one IP
    address (#209861)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=447262"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=447974"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-June/011123.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b132814d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected net-snmp package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(119, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:net-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/12");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"net-snmp-5.4-18.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "net-snmp");
}
