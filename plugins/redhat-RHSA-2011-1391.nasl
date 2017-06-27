#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1391. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56578);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/01/04 16:12:16 $");

  script_cve_id("CVE-2011-3348", "CVE-2011-3368");
  script_bugtraq_id(49616, 49957);
  script_osvdb_id(75647, 76079);
  script_xref(name:"RHSA", value:"2011:1391");

  script_name(english:"RHEL 6 : httpd (RHSA-2011:1391)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated httpd packages that fix two security issues and one bug are
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The Apache HTTP Server is a popular web server.

It was discovered that the Apache HTTP Server did not properly
validate the request URI for proxied requests. In certain
configurations, if a reverse proxy used the ProxyPassMatch directive,
or if it used the RewriteRule directive with the proxy flag, a remote
attacker could make the proxy connect to an arbitrary server, possibly
disclosing sensitive information from internal web servers not
directly accessible to the attacker. (CVE-2011-3368)

It was discovered that mod_proxy_ajp incorrectly returned an 'Internal
Server Error' response when processing certain malformed HTTP
requests, which caused the back-end server to be marked as failed in
configurations where mod_proxy was used in load balancer mode. A
remote attacker could cause mod_proxy to not send requests to back-end
AJP (Apache JServ Protocol) servers for the retry timeout period or
until all back-end servers were marked as failed. (CVE-2011-3348)

Red Hat would like to thank Context Information Security for reporting
the CVE-2011-3368 issue.

This update also fixes the following bug :

* The fix for CVE-2011-3192 provided by the RHSA-2011:1245 update
introduced regressions in the way httpd handled certain Range HTTP
header values. This update corrects those regressions. (BZ#736592)

All httpd users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, the httpd daemon must be restarted for the
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3348.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3368.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://rhn.redhat.com/errata/RHSA-2011-1245.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1391.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:1391";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"httpd-2.2.15-9.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"httpd-2.2.15-9.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"httpd-2.2.15-9.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"httpd-debuginfo-2.2.15-9.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"httpd-devel-2.2.15-9.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"httpd-manual-2.2.15-9.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"httpd-tools-2.2.15-9.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"httpd-tools-2.2.15-9.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"httpd-tools-2.2.15-9.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mod_ssl-2.2.15-9.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"mod_ssl-2.2.15-9.el6_1.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_ssl-2.2.15-9.el6_1.3")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-debuginfo / httpd-devel / httpd-manual / httpd-tools / etc");
  }
}
