#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-13781.
#

include("compat.inc");

if (description)
{
  script_id(78904);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/19 22:14:42 $");

  script_bugtraq_id(70574);
  script_xref(name:"FEDORA", value:"2014-13781");

  script_name(english:"Fedora 20 : python-rhsm-1.13.6-1.fc20 / subscription-manager-1.13.6-1.fc20 (2014-13781)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New features :

  - Send list of compliance reasons on dbus

    - Added client-side support for --matches on the list
      command.

Security :

  - 1153375: Support TLSv1.2 and v1.1 by default.
    (CVE-2014-3566)

Bug fixes :

  - 1120772: Don't traceback on missing /ostree/repo

    - 1094747: add appdata metdata file

    - 1122107: Clarify registration --consumerid option in
      manpage.

    - 1151925: Improved filtered listing output when results
      are empty.

    - 990183: Add a manpage for rhsm.conf

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-November/142781.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c73bbfad"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-November/142782.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc163277"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected python-rhsm and / or subscription-manager
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:python-rhsm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:subscription-manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/07");
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
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"python-rhsm-1.13.6-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"subscription-manager-1.13.6-1.fc20")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-rhsm / subscription-manager");
}
