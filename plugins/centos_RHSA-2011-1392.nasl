#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1392 and 
# CentOS Errata and Security Advisory 2011:1392 respectively.
#

include("compat.inc");

if (description)
{
  script_id(56570);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/05/19 23:52:00 $");

  script_cve_id("CVE-2011-3368");
  script_bugtraq_id(49957);
  script_osvdb_id(76079);
  script_xref(name:"RHSA", value:"2011:1392");

  script_name(english:"CentOS 4 / 5 : httpd (CESA-2011:1392)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated httpd packages that fix one security issue and one bug are now
available for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The Apache HTTP Server is a popular web server.

It was discovered that the Apache HTTP Server did not properly
validate the request URI for proxied requests. In certain
configurations, if a reverse proxy used the ProxyPassMatch directive,
or if it used the RewriteRule directive with the proxy flag, a remote
attacker could make the proxy connect to an arbitrary server, possibly
disclosing sensitive information from internal web servers not
directly accessible to the attacker. (CVE-2011-3368)

Red Hat would like to thank Context Information Security for reporting
this issue.

This update also fixes the following bug :

* The fix for CVE-2011-3192 provided by the RHSA-2011:1245 update
introduced regressions in the way httpd handled certain Range HTTP
header values. This update corrects those regressions. (BZ#736593,
BZ#736594)

All httpd users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, the httpd daemon must be restarted for the
update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-November/018171.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f6b3953b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-November/018172.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a1e80055"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-October/018125.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a0a81143"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-October/018126.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bdf2ade9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-suexec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"httpd-2.0.52-49.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"httpd-2.0.52-49.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"httpd-devel-2.0.52-49.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"httpd-devel-2.0.52-49.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"httpd-manual-2.0.52-49.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"httpd-manual-2.0.52-49.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"httpd-suexec-2.0.52-49.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"httpd-suexec-2.0.52-49.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"mod_ssl-2.0.52-49.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"mod_ssl-2.0.52-49.ent.centos4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"httpd-2.2.3-53.el5.centos.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"httpd-devel-2.2.3-53.el5.centos.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"httpd-manual-2.2.3-53.el5.centos.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mod_ssl-2.2.3-53.el5.centos.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
