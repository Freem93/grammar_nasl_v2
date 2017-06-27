#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2004-152.
#

include("compat.inc");

if (description)
{
  script_id(13712);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:09:31 $");

  script_xref(name:"FEDORA", value:"2004-152");

  script_name(english:"Fedora Core 1 : ethereal-0.10.3-0.1.1 (2004-152)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Issues have been discovered in the following protocol dissectors :

  - A SIP packet could make Ethereal crash under specific
    conditions, as described in the following message:
    http://www.ethereal.com/lists/ethereal-users/200405/msg0
    0018.html (0.10.3).

  - The AIM dissector could throw an assertion, causing
    Ethereal to terminate abnormally (0.10.3).

  - It was possible for the SPNEGO dissector to dereference
    a NULL pointer, causing a crash (0.9.8 to 0.10.3).

    - The MMSE dissector was susceptible to a buffer
      overflow. (0.10.1 to 0.10.3).

All users of Ethereal are strongly encouraged to update to these
latest packages.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ethereal.com/lists/ethereal-users/200405/msg00018.html"
  );
  # https://lists.fedoraproject.org/pipermail/announce/2004-June/000148.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a5e34249"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2004/06/03");
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
if (rpm_check(release:"FC1", reference:"ethereal-0.10.3-0.1.1")) flag++;
if (rpm_check(release:"FC1", reference:"ethereal-debuginfo-0.10.3-0.1.1")) flag++;
if (rpm_check(release:"FC1", reference:"ethereal-gnome-0.10.3-0.1.1")) flag++;


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
