#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0731 and 
# CentOS Errata and Security Advisory 2012:0731 respectively.
#

include("compat.inc");

if (description)
{
  script_id(59482);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/06/14 17:29:26 $");

  script_cve_id("CVE-2012-0876", "CVE-2012-1148");
  script_bugtraq_id(52379);
  script_osvdb_id(80892, 80893);
  script_xref(name:"RHSA", value:"2012:0731");

  script_name(english:"CentOS 5 / 6 : expat (CESA-2012:0731)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated expat packages that fix two security issues are now available
for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Expat is a C library written by James Clark for parsing XML documents.

A denial of service flaw was found in the implementation of hash
arrays in Expat. An attacker could use this flaw to make an
application using Expat consume an excessive amount of CPU time by
providing a specially crafted XML file that triggers multiple hash
function collisions. To mitigate this issue, randomization has been
added to the hash function to reduce the chance of an attacker
successfully causing intentional collisions. (CVE-2012-0876)

A memory leak flaw was found in Expat. If an XML file processed by an
application linked against Expat triggered a memory re-allocation
failure, Expat failed to free the previously allocated memory. This
could cause the application to exit unexpectedly or crash when all
available memory is exhausted. (CVE-2012-1148)

All Expat users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, applications using the Expat library must be
restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-June/018682.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dbbbc400"
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-June/018685.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e92973e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected expat packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:expat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:expat-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"expat-1.95.8-11.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"expat-devel-1.95.8-11.el5_8")) flag++;

if (rpm_check(release:"CentOS-6", reference:"expat-2.0.1-11.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"expat-devel-2.0.1-11.el6_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
