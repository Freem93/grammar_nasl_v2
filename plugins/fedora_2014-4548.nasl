#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-4548.
#

include("compat.inc");

if (description)
{
  script_id(73366);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/19 22:32:18 $");

  script_cve_id("CVE-2013-6393", "CVE-2014-2525");
  script_bugtraq_id(65258);
  script_xref(name:"FEDORA", value:"2014-4548");

  script_name(english:"Fedora 20 : perl-YAML-LibYAML-0.41-4.fc20 (2014-4548)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update addressed two security issues.

CVE-2013-6393: The yaml_parser_scan_tag_uri function in scanner.c in
LibYAML before 0.1.5 performs an incorrect cast, which allows remote
attackers to cause a denial of service (application crash) and
possibly execute arbitrary code via crafted tags in a YAML document,
which triggers a heap-based buffer overflow.

CVE-2014-2525: The library is affected by a heap-based buffer overflow
which can lead to arbitrary code execution. The vulnerability is
caused by lack of proper expansion for the string passed to the
yaml_parser_scan_uri_escapes() function. A specially crafted YAML
file, with a long sequence of percent-encoded characters in a URL, can
be used to trigger the overflow.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1033990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1078083"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-April/131190.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?506f754f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected perl-YAML-LibYAML package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-YAML-LibYAML");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/07");
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
if (rpm_check(release:"FC20", reference:"perl-YAML-LibYAML-0.41-4.fc20")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl-YAML-LibYAML");
}
