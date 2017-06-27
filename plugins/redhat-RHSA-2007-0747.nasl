#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0747. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28240);
  script_version ("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/12/29 15:45:03 $");

  script_cve_id("CVE-2007-3847");
  script_bugtraq_id(25489);
  script_xref(name:"RHSA", value:"2007:0747");

  script_name(english:"RHEL 4 : httpd (RHSA-2007:0747)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated httpd packages that fix a security issue, various bugs, and
add enhancements are now available for Red Hat Enterprise Linux 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Apache HTTP Server is a popular and freely-available Web server.

A flaw was found in the Apache HTTP Server mod_proxy module. On sites
where a reverse proxy is configured, a remote attacker could send a
carefully crafted request that would cause the Apache child process
handling that request to crash. On sites where a forward proxy is
configured, an attacker could cause a similar crash if a user could be
persuaded to visit a malicious site using the proxy. This could lead
to a denial of service if using a threaded Multi-Processing Module.
(CVE-2007-3847)

As well, these updated packages fix the following bugs :

* the default '/etc/logrotate.d/httpd' script incorrectly invoked the
kill command, instead of using the '/sbin/service httpd restart'
command. If you configured the httpd PID to be in a location other
than '/var/run/httpd.pid', the httpd logs failed to be rotated. This
has been resolved in these updated packages.

* Set-Cookie headers with a status code of 3xx are not forwarded to
clients when the 'ProxyErrorOverride' directive is enabled. These
responses are overridden at the proxy. Only the responses with status
codes of 4xx and 5xx are overridden in these updated packages.

* mod_proxy did not correctly handle percent-encoded characters (ie
%20) when configured as a reverse proxy.

* invalid HTTP status codes could be logged if output filters returned
errors.

* the 'ProxyTimeout' directive was not inherited across virtual host
definitions.

* in some cases the Content-Length header was dropped from HEAD
responses. This resulted in certain sites not working correctly with
mod_proxy, such as www.windowsupdate.com.

This update adds the following enhancements :

* a new configuration option has been added, 'ServerTokens
Full-Release', which adds the package release to the server version
string, which is returned in the 'Server' response header.

* a new module has been added, mod_version, which allows configuration
files to be written containing sections, which are evaluated only if
the version of httpd used matches a specified condition.

Users of httpd are advised to upgrade to these updated packages, which
resolve these issues and add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-3847.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2007-0747.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-suexec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2007:0747";
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
  if (rpm_check(release:"RHEL4", reference:"httpd-2.0.52-38.ent")) flag++;
  if (rpm_check(release:"RHEL4", reference:"httpd-devel-2.0.52-38.ent")) flag++;
  if (rpm_check(release:"RHEL4", reference:"httpd-manual-2.0.52-38.ent")) flag++;
  if (rpm_check(release:"RHEL4", reference:"httpd-suexec-2.0.52-38.ent")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mod_ssl-2.0.52-38.ent")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-devel / httpd-manual / httpd-suexec / mod_ssl");
  }
}
