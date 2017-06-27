#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-14179.
#

include("compat.inc");

if (description)
{
  script_id(62335);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/20 22:25:13 $");

  script_cve_id("CVE-2012-4415");
  script_bugtraq_id(55497);
  script_xref(name:"FEDORA", value:"2012-14179");

  script_name(english:"Fedora 17 : guacamole-common-0.6.1-2.fc17 / guacamole-common-js-0.6.1-2.fc17 / etc (2012-14179)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Guacamole C stack rebuild

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=856743"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-September/088212.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85831a2e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-September/088213.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3be7ba99"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-September/088214.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?09bcfff1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-September/088215.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?55fb42b7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-September/088216.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75f4e72d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-September/088217.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bafd7f5d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-September/088218.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c00f9721"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:guacamole-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:guacamole-common-js");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:guacamole-ext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:guacd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libguac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libguac-client-rdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libguac-client-vnc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:17");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/27");
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
if (rpm_check(release:"FC17", reference:"guacamole-common-0.6.1-2.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"guacamole-common-js-0.6.1-2.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"guacamole-ext-0.6.1-2.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"guacd-0.6.1-3.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"libguac-0.6.3-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"libguac-client-rdp-0.6.1-2.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"libguac-client-vnc-0.6.0-8.fc17")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "guacamole-common / guacamole-common-js / guacamole-ext / guacd / etc");
}
