#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:0703 and 
# Oracle Linux Security Advisory ELSA-2014-0703 respectively.
#

include("compat.inc");

if (description)
{
  script_id(76736);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 17:25:14 $");

  script_cve_id("CVE-2013-6370", "CVE-2013-6371");
  script_bugtraq_id(66715, 66720);
  script_xref(name:"RHSA", value:"2014:0703");

  script_name(english:"Oracle Linux 7 : json-c (ELSA-2014-0703)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2014:0703 :

Updated json-c packages that fix two security issues are now available
for Red Hat Enterprise Linux 7.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

JSON-C implements a reference counting object model that allows you to
easily construct JSON objects in C, output them as JSON-formatted
strings, and parse JSON-formatted strings back into the C
representation of JSON objects.

Multiple buffer overflow flaws were found in the way the json-c
library handled long strings in JSON documents. An attacker able to
make an application using json-c parse excessively large JSON input
could cause the application to crash. (CVE-2013-6370)

A denial of service flaw was found in the implementation of hash
arrays in json-c. An attacker could use this flaw to make an
application using json-c consume an excessive amount of CPU time by
providing a specially crafted JSON document that triggers multiple
hash function collisions. To mitigate this issue, json-c now uses a
different hash function and randomization to reduce the chance of an
attacker successfully causing intentional collisions. (CVE-2013-6371)

These issues were discovered by Florian Weimer of the Red Hat Product
Security Team.

All json-c users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-July/004279.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected json-c packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:json-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:json-c-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:json-c-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"json-c-0.11-4.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"json-c-devel-0.11-4.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"json-c-doc-0.11-4.el7_0")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "json-c / json-c-devel / json-c-doc");
}
