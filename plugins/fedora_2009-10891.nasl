#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-10891.
#

include("compat.inc");

if (description)
{
  script_id(42935);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/08 20:21:54 $");

  script_cve_id("CVE-2009-2820", "CVE-2009-3553");
  script_bugtraq_id(36958, 37048);
  script_xref(name:"FEDORA", value:"2009-10891");

  script_name(english:"Fedora 11 : cups-1.4.2-7.fc11 (2009-10891)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated to 1.4.2 including XSS security fix (CVE-2009-2820). Fixed
improper reference counting in abstract file descriptors handling
interface (CVE-2009-3553). Fixed admin.cgi crash when modifying a
class. Fix cups-lpd to create unique temporary data files. Pass
through serial parameters correctly in web interface. Set the
PRINTER_IS_SHARED variable for admin.cgi Fix removing files with lprm.
Fixed German translation. Fixed PostScript errors with number-up
handling. Fixed lspp-patch to avoid memory leak. Upstream fix for GNU
TLS error handling bug. Reset SIGPIPE handler for child processes.
Fixed typo in admin web template. Fixed incorrect handling of
out-of-memory when loading jobs. Fixed wrong driver reported in web
interface.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=529833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=530111"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-December/031831.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82dcce0a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:cups");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/01");
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
if (rpm_check(release:"FC11", reference:"cups-1.4.2-7.fc11")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups");
}
