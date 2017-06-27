#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2003-040.
#

include("compat.inc");

if (description)
{
  script_id(13668);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:09:30 $");

  script_xref(name:"FEDORA", value:"2003-040");

  script_name(english:"Fedora Core 1 : ethereal-0.10.0a-0.1 (2003-040)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Serious issues have been discovered in the following protocol
dissectors :

  - Selecting 'Match->Selected' or 'Prepare->Selected' for a
    malformed SMB packet could cause a segmentation fault.

  - It is possible for the Q.931 dissector to dereference a
    NULL pointer when reading a malformed packet.

Impact :

Both vulnerabilities will make the Ethereal application crash. The
Q.931 vulnerability also affects Tethereal. It is not known if either
vulnerability can be used to make Ethereal or Tethereal run arbitrary
code.

Resolution :

Upgrade to 0.10.0.

If you are running a version prior to 0.10.0 and you cannot upgrade,
you can disable the SMB and Q.931 protocol dissectors by selecting
Edit->Protocols... and deselecting them from the list.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2003-December/000025.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4c07bcb9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected ethereal, ethereal-debuginfo and / or
ethereal-gnome packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ethereal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ethereal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ethereal-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/12/18");
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
if (rpm_check(release:"FC1", cpu:"i386", reference:"ethereal-0.10.0a-0.1")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"ethereal-debuginfo-0.10.0a-0.1")) flag++;
if (rpm_check(release:"FC1", cpu:"i386", reference:"ethereal-gnome-0.10.0a-0.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ethereal / ethereal-debuginfo / ethereal-gnome");
}
