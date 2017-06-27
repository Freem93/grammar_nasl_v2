#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2522 and 
# CentOS Errata and Security Advisory 2015:2522 respectively.
#

include("compat.inc");

if (description)
{
  script_id(87161);
  script_version("$Revision: 2.12 $");
  script_cvs_date("$Date: 2016/05/08 04:42:33 $");

  script_cve_id("CVE-2015-7501");
  script_osvdb_id(130493);
  script_xref(name:"RHSA", value:"2015:2522");

  script_name(english:"CentOS 7 : apache-commons-collections (CESA-2015:2522)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated apache-commons-collections packages that fix one security
issue are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The Apache Commons Collections library provides new interfaces,
implementations, and utilities to extend the features of the Java
Collections Framework.

It was found that the Apache commons-collections library permitted
code execution when deserializing objects involving a specially
constructed chain of classes. A remote attacker could use this flaw to
execute arbitrary code with the permissions of the application using
the commons-collections library. (CVE-2015-7501)

With this update, deserialization of certain classes in the
commons-collections library is no longer allowed. Applications that
require those classes to be deserialized can use the system property
'org.apache.commons.collections.enableUnsafeSerialization' to
re-enable their deserialization.

Further information about this security flaw may be found at:
https://access.redhat.com/solutions/2045023

All users of apache-commons-collections are advised to upgrade to
these updated packages, which contain a backported patch to correct
this issue. All running applications using the commons-collections
library must be restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-December/002725.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?49459f17"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache-commons-collections packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:apache-commons-collections");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:apache-commons-collections-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:apache-commons-collections-testframework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:apache-commons-collections-testframework-javadoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"apache-commons-collections-3.2.1-22.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"apache-commons-collections-javadoc-3.2.1-22.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"apache-commons-collections-testframework-3.2.1-22.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"apache-commons-collections-testframework-javadoc-3.2.1-22.el7_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
