#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2004-115.
#

include("compat.inc");

if (description)
{
  script_id(13694);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/10/21 21:09:31 $");

  script_cve_id("CVE-2003-0856");
  script_xref(name:"FEDORA", value:"2004-115");

  script_name(english:"Fedora Core 1 : iproute-2.4.7-13.2 (2004-115)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of the iproute package fixes a security problem found in
netlink. See CVE-2003-0856.

All users of the netlink application are very strongly advised to
update to these latest packages.

  - Thu May 06 2004 Phil Knirsch <pknirsch at redhat.com>
    2.4.7-13.2

  - Built security errata version for FC1.

  - Wed Apr 21 2004 Phil Knirsch <pknirsch at redhat.com>
    2.4.7-14

  - Fixed -f option for ss (#118355).

    - Small description fix (#110997).

    - Added initialization of some vars (#74961).

    - Added patch to initialize 'default' rule as well
      (#60693).

  - Fri Feb 13 2004 Elliot Lee <sopwith at redhat.com>

  - rebuilt

  - Wed Nov 05 2003 Phil Knirsch <pknirsch at redhat.com>
    2.4.7-12

  - Security errata for netlink (CVE-2003-0856).

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2004-May/000118.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5008932e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected iproute and / or iproute-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:iproute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:iproute-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 1.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC1", reference:"iproute-2.4.7-13.2")) flag++;
if (rpm_check(release:"FC1", reference:"iproute-debuginfo-2.4.7-13.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "iproute / iproute-debuginfo");
}
