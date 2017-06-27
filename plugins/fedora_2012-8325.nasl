#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-8325.
#

include("compat.inc");

if (description)
{
  script_id(59338);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/09 15:36:31 $");

  script_bugtraq_id(53626, 53627, 53629, 53632);
  script_xref(name:"FEDORA", value:"2012-8325");

  script_name(english:"Fedora 16 : moodle-2.0.9-1.fc16 (2012-8325)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2012-2353 MSA-12-0024: Hidden information access issue
CVE-2012-2354 MSA-12-0025: Personal communication access issue
CVE-2012-2355 MSA-12-0026: Quiz capability issue CVE-2012-2356
MSA-12-0027: Question bank capability issues CVE-2012-2357
MSA-12-0028: Insecure authentication issue CVE-2012-2358 MSA-12-0029:
Information editing access issue CVE-2012-2359 MSA-12-0030: Capability
manipulation issue CVE-2012-2360 MSA-12-0031: Cross-site scripting
vulnerability in Wiki CVE-2012-2361 MSA-12-0032: Cross-site scripting
vulnerability in Web services CVE-2012-2362 MSA-12-0033: Cross-site
scripting vulnerability in Blog CVE-2012-2363 MSA-12-0034: Potential
SQL injection issue CVE-2012-2364 MSA-12-0035: Cross-site scripting
vulnerability in 'download all' CVE-2012-2365 MSA-12-0036: Cross-site
scripting vulnerability in category identifier CVE-2012-2366
MSA-12-0037: Write access issue in Database activity module
CVE-2012-2367 MSA-12-0038: Calendar event write permission issue
Correct CAS unbundling. Drop bundled language packs. New upstreams,
multiple vulnerabilities.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-June/081681.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f5c3b83"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected moodle package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:16");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^16([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 16.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC16", reference:"moodle-2.0.9-1.fc16")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "moodle");
}
