#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-8429.
#

include("compat.inc");

if (description)
{
  script_id(34309);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/08 20:21:54 $");

  script_cve_id("CVE-2008-0016", "CVE-2008-3835", "CVE-2008-3837", "CVE-2008-4058", "CVE-2008-4059", "CVE-2008-4060", "CVE-2008-4061", "CVE-2008-4062", "CVE-2008-4065", "CVE-2008-4066", "CVE-2008-4067", "CVE-2008-4068", "CVE-2008-4069");
  script_xref(name:"FEDORA", value:"2008-8429");

  script_name(english:"Fedora 9 : seamonkey-1.1.12-1.fc9 (2008-8429)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated seamonkey packages that fix several security issues are now
available for Fedora 8 and Fedora 9. This update has been rated as
having critical security impact by the Red Hat Security Response Team.
SeaMonkey is an open source Web browser, advanced email and newsgroup
client, IRC chat client, and HTML editor. Several flaws were found in
the processing of malformed web content. A web page containing
malicious content could cause SeaMonkey to crash or, potentially,
execute arbitrary code as the user running SeaMonkey. (CVE-2008-0016,
CVE-2008-4058, CVE-2008-4059, CVE-2008-4060, CVE-2008-4061,
CVE-2008-4062) Several flaws were found in the way malformed web
content was displayed. A web page containing specially crafted content
could potentially trick a SeaMonkey user into surrendering sensitive
information. (CVE-2008-3835, CVE-2008-4067, CVE-2008-4068,
CVE-2008-4069) A flaw was found in the way SeaMonkey handles mouse
click events. A web page containing specially crafted JavaScript code
could move the content window while a mouse-button was pressed,
causing any item under the pointer to be dragged. This could,
potentially, cause the user to perform an unsafe drag-and-drop action.
(CVE-2008-3837) A flaw was found in SeaMonkey that caused certain
characters to be stripped from JavaScript code. This flaw could allow
malicious JavaScript to bypass or evade script filters.
(CVE-2008-4065, CVE-2008-4066) All SeaMonkey users should upgrade to
these updated packages, which contain patches to resolve these issues.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014934.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6cec37da"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(22, 79, 119, 189, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:seamonkey");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 9.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC9", reference:"seamonkey-1.1.12-1.fc9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "seamonkey");
}
