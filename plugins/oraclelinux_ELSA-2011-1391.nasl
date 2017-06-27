#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:1391 and 
# Oracle Linux Security Advisory ELSA-2011-1391 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68376);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/12/01 16:58:00 $");

  script_cve_id("CVE-2011-3348", "CVE-2011-3368");
  script_bugtraq_id(49303, 49616, 49957, 50312);
  script_osvdb_id(75647, 76079);
  script_xref(name:"RHSA", value:"2011:1391");

  script_name(english:"Oracle Linux 6 : httpd (ELSA-2011-1391)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:1391 :

Updated httpd packages that fix two security issues and one bug are
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
    value:"https://oss.oracle.com/pipermail/el-errata/2011-October/002419.html"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/21");
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
if (rpm_check(release:"EL6", reference:"httpd-2.2.15-9.0.1.el6_1.3")) flag++;
if (rpm_check(release:"EL6", reference:"httpd-devel-2.2.15-9.0.1.el6_1.3")) flag++;
if (rpm_check(release:"EL6", reference:"httpd-manual-2.2.15-9.0.1.el6_1.3")) flag++;
if (rpm_check(release:"EL6", reference:"httpd-tools-2.2.15-9.0.1.el6_1.3")) flag++;
if (rpm_check(release:"EL6", reference:"mod_ssl-2.2.15-9.0.1.el6_1.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-devel / httpd-manual / httpd-tools / mod_ssl");
}
