#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0320 and 
# Oracle Linux Security Advisory ELSA-2011-0320 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68218);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:57:59 $");

  script_cve_id("CVE-2011-1006", "CVE-2011-1022");
  script_bugtraq_id(46578, 46729);
  script_osvdb_id(72519);
  script_xref(name:"RHSA", value:"2011:0320");

  script_name(english:"Oracle Linux 6 : libcgroup (ELSA-2011-0320)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0320 :

Updated libcgroup packages that fix two security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The libcgroup packages provide tools and libraries to control and
monitor control groups.

A heap-based buffer overflow flaw was found in the way libcgroup
converted a list of user-provided controllers for a particular task
into an array of strings. A local attacker could use this flaw to
escalate their privileges via a specially crafted list of controllers.
(CVE-2011-1006)

It was discovered that libcgroup did not properly check the origin of
Netlink messages. A local attacker could use this flaw to send crafted
Netlink messages to the cgrulesengd daemon, causing it to put
processes into one or more existing control groups, based on the
attacker's choosing, possibly allowing the particular tasks to run
with more resources (memory, CPU, etc.) than originally intended.
(CVE-2011-1022)

Red Hat would like to thank Nelson Elhage for reporting the
CVE-2011-1006 issue.

All libcgroup users should upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-March/001975.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libcgroup packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libcgroup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libcgroup-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libcgroup-pam");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"libcgroup-0.36.1-6.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"libcgroup-devel-0.36.1-6.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"libcgroup-pam-0.36.1-6.el6_0.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcgroup / libcgroup-devel / libcgroup-pam");
}
