#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-15461.
#

include("compat.inc");

if (description)
{
  script_id(49939);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/11 13:16:09 $");

  script_bugtraq_id(43573);
  script_xref(name:"FEDORA", value:"2010-15461");

  script_name(english:"Fedora 14 : bind-9.7.2-2.P2.fc14 / bind-dyndb-ldap-0.1.0-0.14.b.fc14 / dnsperf-1.0.1.0-21.fc14 (2010-15461)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to 9.7.2-P2 security release. Check
https://lists.isc.org/pipermail/bind-announce/2010-September/000655.ht
ml for more information.

Packages dnsperf and bind-dyndb-ldap needed to be rebuilt.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-October/049203.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?afb4c975"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-October/049204.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?736bb2f2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-October/049205.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca2ca0c2"
  );
  # https://lists.isc.org/pipermail/bind-announce/2010-September/000655.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?43b5fc2d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bind, bind-dyndb-ldap and / or dnsperf packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bind-dyndb-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dnsperf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^14([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 14.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC14", reference:"bind-9.7.2-2.P2.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"bind-dyndb-ldap-0.1.0-0.14.b.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"dnsperf-1.0.1.0-21.fc14")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-dyndb-ldap / dnsperf");
}
