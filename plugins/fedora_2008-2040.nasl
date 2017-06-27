#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-2040.
#

include("compat.inc");

if (description)
{
  script_id(31311);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/10/21 22:13:38 $");

  script_cve_id("CVE-2007-6018", "CVE-2008-0807");
  script_bugtraq_id(27223);
  script_xref(name:"FEDORA", value:"2008-2040");

  script_name(english:"Fedora 7 : horde-3.1.6-1.fc7 / imp-4.1.6-1.fc7 / turba-2.1.7-1.fc7 (2008-2040)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Fedora host is missing one or more security updates :

imp-4.1.6-1.fc7 :

  - Mon Jan 14 2008 Brandon Holbrook <fedora at
    theholbrooks.org> 4.1.6-1

    - Upgraded to 4.1.6

    - Sat Oct 20 2007 Brandon Holbrook <fedora at
      theholbrooks.org> 4.1.5-1

    - Upgraded to 4.1.5

horde-3.1.6-1.fc7 :

  - Fri Jan 11 2008 Brandon Holbrook <fedora at
    theholbrooks.org> 3.1.6-1

    - Update to 3.1.6

    - Sat Oct 20 2007 Brandon Holbrook <fedora at
      theholbrooks.org> 3.1.5-1

    - Update to 3.1.5

turba-2.1.7-1.fc7 :

  - Tue Feb 26 2008 Jan ONDREJ (SAL) <ondrejj(at)salstar.sk>
    2.1.7-1

    - Update to upstream: CVE-2008-0807: turba: insufficient
      access checks

    - Mon Jan 14 2008 Brandon Holbrook <fedora at
      theholbrooks.org> 2.1.6-1

    - Upgraded to 2.1.6

    - Sat Oct 20 2007 Brandon Holbrook <fedora at
      theholbrooks.org> 2.1.5-1

    - Upgraded to 2.1.5

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=428625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=432027"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/008268.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1f41fb37"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/008269.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?afc00baf"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/008270.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e45702f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected horde, imp and / or turba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:horde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:imp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:turba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/29");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"horde-3.1.6-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"imp-4.1.6-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"turba-2.1.7-1.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "horde / imp / turba");
}
