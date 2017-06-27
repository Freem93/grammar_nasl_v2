#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-15588.
#

include("compat.inc");

if (description)
{
  script_id(79777);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/19 22:14:43 $");

  script_cve_id("CVE-2014-8958", "CVE-2014-8959", "CVE-2014-8960", "CVE-2014-8961");
  script_bugtraq_id(71243, 71244, 71245, 71247);
  script_xref(name:"FEDORA", value:"2014-15588");

  script_name(english:"Fedora 21 : phpMyAdmin-4.2.12-1.fc21 (2014-15588)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"phpMyAdmin 4.2.12.0 (2014-11-20) ================================

  - Blank/white page when JavaScript disabled

    - Multi row actions cause full page reloads

    - ReferenceError: targeurl is not defined

    - Incorrect text/icon display in Tracking report

    - Recordset return from procedure display nothing

    - Edit dialog for routines is too long for smaller
      displays

    - JavaScript error after moving a column

    - Issue with long comments on table columns

    - Input field unnecessarily selected on focus

    - Exporting selected rows exports all rows of the query

    - No insert statement produced in SQL export for queries
      with alias

    - Field disabled when internal relations used

    - [security] XSS through exception stack

    - [security] Path traversal can lead to leakage of line
      count

    - [security] XSS vulnerability in table print view

    - [security] XSS vulnerability in zoom search page

    - [security] Path traversal in file inclusion of GIS
      factory

    - [security] XSS in multi submit

    - [security] XSS through pma_fontsize cookie

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1166619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1166626"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1166634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1166637"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-December/145389.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?19823dc5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpMyAdmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:21");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/07");
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
if (! ereg(pattern:"^21([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 21.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC21", reference:"phpMyAdmin-4.2.12-1.fc21")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phpMyAdmin");
}
