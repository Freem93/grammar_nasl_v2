#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-19125.
#

include("compat.inc");

if (description)
{
  script_id(63235);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/20 22:44:19 $");

  script_cve_id("CVE-2012-5526");
  script_bugtraq_id(56562);
  script_xref(name:"FEDORA", value:"2012-19125");

  script_name(english:"Fedora 18 : perl-5.16.2-235.fc18 / perl-CGI-3.59-235.fc18 (2012-19125)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fix CVE-2012-5526 (escape new-lines in Set-Cookie and P3P HTTP
response headers properly) in CGI-3.59.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=877015"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-December/094546.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d14d3da"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-December/094547.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?32eb71d9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected perl and / or perl-CGI packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-CGI");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/12");
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
if (! ereg(pattern:"^18([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 18.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC18", reference:"perl-5.16.2-235.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"perl-CGI-3.59-235.fc18")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl / perl-CGI");
}
