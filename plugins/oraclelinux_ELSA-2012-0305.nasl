#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:0305 and 
# Oracle Linux Security Advisory ELSA-2012-0305 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68476);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/06 17:02:14 $");

  script_cve_id("CVE-2008-0171", "CVE-2008-0172");
  script_bugtraq_id(27325);
  script_osvdb_id(42790, 42791);
  script_xref(name:"RHSA", value:"2012:0305");

  script_name(english:"Oracle Linux 5 : boost (ELSA-2012-0305)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:0305 :

Updated boost packages that fix two security issues and two bugs are
now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The boost packages provide free, peer-reviewed, portable C++ source
libraries with emphasis on libraries which work well with the C++
Standard Library.

Invalid pointer dereference flaws were found in the way the Boost
regular expression library processed certain, invalid expressions. An
attacker able to make an application using the Boost library process a
specially crafted regular expression could cause that application to
crash or, potentially, execute arbitrary code with the privileges of
the user running the application. (CVE-2008-0171)

NULL pointer dereference flaws were found in the way the Boost regular
expression library processed certain, invalid expressions. An attacker
able to make an application using the Boost library process a
specially crafted regular expression could cause that application to
crash. (CVE-2008-0172)

Red Hat would like to thank Will Drewry for reporting these issues.

This update also fixes the following bugs :

* Prior to this update, the construction of a regular expression
object could fail when several regular expression objects were created
simultaneously, such as in a multi-threaded program. With this update,
the object variables have been moved from the shared memory to the
stack. Now, the constructing function is thread safe. (BZ#472384)

* Prior to this update, header files in several Boost libraries
contained preprocessor directives that the GNU Compiler Collection
(GCC) 4.4 could not handle. This update instead uses equivalent
constructs that are standard C. (BZ#567722)

All users of boost are advised to upgrade to these updated packages,
which fix these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-March/002656.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected boost packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:boost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:boost-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:boost-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/07");
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
if (rpm_check(release:"EL5", reference:"boost-1.33.1-15.el5")) flag++;
if (rpm_check(release:"EL5", reference:"boost-devel-1.33.1-15.el5")) flag++;
if (rpm_check(release:"EL5", reference:"boost-doc-1.33.1-15.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "boost / boost-devel / boost-doc");
}
