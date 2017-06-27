#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-9001.
#

include("compat.inc");

if (description)
{
  script_id(59438);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/20 22:53:53 $");

  script_xref(name:"FEDORA", value:"2012-9001");

  script_name(english:"Fedora 17 : thunderbird-13.0-1.fc17 / thunderbird-lightning-1.5-2.fc17 (2012-9001)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"What is new :

  - Filelink: Upload your files to an online storage service
    and send links to your friends, avoiding bounce back due
    to large attachments. We have partnered with YouSendIt
    to bring this feature, but additional partners will be
    added in the near future.

    - In partnership with Gandi and Hover, you can now sign
      up for a personalized email address from within
      Thunderbird. Along with your new email address,
      Thunderbird will be automatically set up and ready to
      send and receive messages. We are working with
      additional suppliers to cover more areas of the world
      and to provide more options in the future.

What is fixed :

  - Various security fixes

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-June/082048.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f72a76cf"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-June/082049.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ffd99b3b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected thunderbird and / or thunderbird-lightning
packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird-lightning");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:17");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC17", reference:"thunderbird-13.0-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"thunderbird-lightning-1.5-2.fc17")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird / thunderbird-lightning");
}
