#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60295);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/06/03 10:41:59 $");

  script_cve_id("CVE-2007-3847");

  script_name(english:"Scientific Linux Security Update : httpd on SL5.x");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Problem description :

A flaw was found in the Apache HTTP Server mod_proxy module. On sites
where a reverse proxy is configured, a remote attacker could send a
carefully crafted request that would cause the Apache child process
handling that request to crash. On sites where a forward proxy is
configured, an attacker could cause a similar crash if a user could be
persuaded to visit a malicious site using the proxy. This could lead
to a denial of service if using a threaded Multi-Processing Module.
(CVE-2007-3847)

As well, these updated packages fix the following bugs :

  - Set-Cookie headers with a status code of 3xx are not
    forwarded to clients when the 'ProxyErrorOverride'
    directive is enabled. These responses are overridden at
    the proxy. Only the responses with status codes of 4xx
    and 5xx are overridden in these updated packages.

  - the default '/etc/logrotate.d/httpd' script incorrectly
    invoked the kill command, instead of using the
    '/sbin/service httpd restart' command. If you configured
    the httpd PID to be in a location other than
    '/var/run/httpd.pid', the httpd logs failed to be
    rotated. This has been resolved in these updated
    packages.

  - the 'ProxyTimeout' directive was not inherited across
    virtual host definitions.

  - the logresolve utility was unable to read lines longer
    the 1024 bytes.

This update adds the following enhancements :

  - a new configuration option has been added, 'ServerTokens
    Full-Release', which adds the package release to the
    server version string, which is returned in the 'Server'
    response header.

  - a new module has been added, mod_version, which allows
    configuration files to be written containing sections,
    which are evaluated only if the version of httpd used
    matches a specified condition."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0711&L=scientific-linux-errata&T=0&P=1086
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dbec8e22"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"httpd-2.2.3-11.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"httpd-devel-2.2.3-11.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"httpd-manual-2.2.3-11.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"mod_ssl-2.2.3-11.sl5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
