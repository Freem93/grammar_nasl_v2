#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1695 and 
# CentOS Errata and Security Advisory 2015:1695 respectively.
#

include("compat.inc");

if (description)
{
  script_id(86500);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/01/27 23:31:26 $");

  script_cve_id("CVE-2015-0254");
  script_osvdb_id(118922);
  script_xref(name:"RHSA", value:"2015:1695");

  script_name(english:"CentOS 6 / 7 : jakarta-taglibs-standard (CESA-2015:1695)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated jakarta-taglibs-standard packages that fix one security issue
are now available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

jakarta-taglibs-standard is the Java Standard Tag Library (JSTL). This
library is used in conjunction with Tomcat and Java Server Pages
(JSP).

It was found that the Java Standard Tag Library (JSTL) allowed the
processing of untrusted XML documents to utilize external entity
references, which could access resources on the host system and,
potentially, allowing arbitrary code execution. (CVE-2015-0254)

Note: jakarta-taglibs-standard users may need to take additional steps
after applying this update. Detailed instructions on the additional
steps can be found here :

https://access.redhat.com/solutions/1584363

All jakarta-taglibs-standard users are advised to upgrade to these
updated packages, which contain a backported patch to correct this
issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-September/021358.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d52ba557"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-September/021359.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?da44adf6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected jakarta-taglibs-standard packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:jakarta-taglibs-standard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:jakarta-taglibs-standard-javadoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"jakarta-taglibs-standard-1.1.1-11.7.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"jakarta-taglibs-standard-javadoc-1.1.1-11.7.el6_7")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"jakarta-taglibs-standard-1.1.2-14.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"jakarta-taglibs-standard-javadoc-1.1.2-14.el7_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
