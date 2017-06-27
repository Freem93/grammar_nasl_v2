#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0429 and 
# CentOS Errata and Security Advisory 2014:0429 respectively.
#

include("compat.inc");

if (description)
{
  script_id(73675);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/20 13:54:06 $");

  script_cve_id("CVE-2012-3544", "CVE-2013-4286", "CVE-2013-4322", "CVE-2014-0050");
  script_bugtraq_id(65400, 65767, 65773);
  script_osvdb_id(102945, 103706, 103708);
  script_xref(name:"RHSA", value:"2014:0429");

  script_name(english:"CentOS 6 : tomcat6 (CESA-2014:0429)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tomcat6 packages that fix three security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Apache Tomcat is a servlet container for the Java Servlet and
JavaServer Pages (JSP) technologies.

It was found that when Tomcat processed a series of HTTP requests in
which at least one request contained either multiple content-length
headers, or one content-length header with a chunked transfer-encoding
header, Tomcat would incorrectly handle the request. A remote attacker
could use this flaw to poison a web cache, perform cross-site
scripting (XSS) attacks, or obtain sensitive information from other
requests. (CVE-2013-4286)

It was discovered that the fix for CVE-2012-3544 did not properly
resolve a denial of service flaw in the way Tomcat processed chunk
extensions and trailing headers in chunked requests. A remote attacker
could use this flaw to send an excessively long request that, when
processed by Tomcat, could consume network bandwidth, CPU, and memory
on the Tomcat server. Note that chunked transfer encoding is enabled
by default. (CVE-2013-4322)

A denial of service flaw was found in the way Apache Commons
FileUpload handled small-sized buffers used by MultipartStream. A
remote attacker could use this flaw to create a malformed Content-Type
header for a multipart request, causing JBoss Web to enter an infinite
loop when processing such an incoming request. (CVE-2014-0050)

All Tomcat users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. Tomcat must
be restarted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-April/020265.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0779aa15"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat6 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat6-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat6-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat6-el-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat6-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat6-jsp-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat6-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat6-servlet-2.5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat6-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"tomcat6-6.0.24-64.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-admin-webapps-6.0.24-64.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-docs-webapp-6.0.24-64.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-el-2.1-api-6.0.24-64.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-javadoc-6.0.24-64.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-jsp-2.1-api-6.0.24-64.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-lib-6.0.24-64.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-servlet-2.5-api-6.0.24-64.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-webapps-6.0.24-64.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
