#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-12000.
#

include("compat.inc");

if (description)
{
  script_id(78375);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/19 22:06:08 $");

  script_cve_id("CVE-2014-7154", "CVE-2014-7155", "CVE-2014-7156", "CVE-2014-7188");
  script_bugtraq_id(70055, 70057, 70062, 70198);
  script_xref(name:"FEDORA", value:"2014-12000");

  script_name(english:"Fedora 19 : xen-4.2.5-3.fc19 (2014-12000)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Improper MSR range used for x2APIC emulation [XSA-108, CVE-2014-7188]
Race condition in HVMOP_track_dirty_vram [XSA-104] (#1145736) Missing
privilege level checks in x86 HLT, LGDT, LIDT, and LMSW emulation
[XSA-105] (#1145737) Missing privilege level checks in x86 emulation
of software interrupts [XSA-106] (#1145738)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1140254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1140266"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1140271"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1144499"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-October/140483.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5dee5b3e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen package.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:19");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^19([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 19.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC19", reference:"xen-4.2.5-3.fc19")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
