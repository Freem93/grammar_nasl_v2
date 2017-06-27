#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0122 and 
# Oracle Linux Security Advisory ELSA-2013-0122 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68693);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/07 20:57:51 $");

  script_cve_id("CVE-2007-4772", "CVE-2007-6067");
  script_bugtraq_id(27163);
  script_osvdb_id(40902, 40905);
  script_xref(name:"RHSA", value:"2013:0122");

  script_name(english:"Oracle Linux 5 : tcl (ELSA-2013-0122)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:0122 :

Updated tcl packages that fix two security issues and one bug are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Tcl (Tool Command Language) provides a powerful platform for creating
integration applications that tie together diverse applications,
protocols, devices, and frameworks. When paired with the Tk toolkit,
Tcl provides a fast and powerful way to create cross-platform GUI
applications.

Two denial of service flaws were found in the Tcl regular expression
handling engine. If Tcl or an application using Tcl processed a
specially crafted regular expression, it would lead to excessive CPU
and memory consumption. (CVE-2007-4772, CVE-2007-6067)

This update also fixes the following bug :

* Due to a suboptimal implementation of threading in the current
version of the Tcl language interpreter, an attempt to use threads in
combination with fork in a Tcl script could cause the script to stop
responding. At the moment, it is not possible to rewrite the source
code or drop support for threading entirely. Consequent to this, this
update provides a version of Tcl without threading support in addition
to the standard version with this support. Users who need to use fork
in their Tcl scripts and do not require threading can now switch to
the version without threading support by using the alternatives
command. (BZ#478961)

All users of Tcl are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-January/003193.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tcl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tcl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tcl-html");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"tcl-8.4.13-6.el5")) flag++;
if (rpm_check(release:"EL5", reference:"tcl-devel-8.4.13-6.el5")) flag++;
if (rpm_check(release:"EL5", reference:"tcl-html-8.4.13-6.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tcl / tcl-devel / tcl-html");
}
