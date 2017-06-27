#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-13634.
#

include("compat.inc");

if (description)
{
  script_id(43607);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/08 20:21:54 $");

  script_cve_id("CVE-2010-0004", "CVE-2010-0005");
  script_xref(name:"FEDORA", value:"2009-13634");

  script_name(english:"Fedora 11 : viewvc-1.1.3-1.fc11 (2009-13634)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - security fix: add root listing support of per-root authz
    config * security fix: query.py requires 'forbidden'
    authorizer (or none) in config * fix URL- ification of
    truncated log messages (issue #3) * fix regexp input
    validation (issue #426, #427, #440) * add support for
    configurable tab-to-spaces conversion * fix
    not-a-sequence error in diff view * allow viewvc-install
    to work when templates-contrib is absent * minor
    template improvements/corrections

  - expose revision metadata in diff view (issue #431) *
    markup file/directory item property URLs and email
    addresses (issue #434) * make ViewVC cross copies in
    Subversion history by default * fix bug that caused
    standalone.py failure under Python 1.5.2 (issue #442) *
    fix support for per-vhost overrides of authorizer
    parameters (issue #411) * fix root name identification
    in query.py interface

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-December/033273.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a90883e7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected viewvc package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:viewvc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^11([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 11.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC11", reference:"viewvc-1.1.3-1.fc11")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "viewvc");
}
