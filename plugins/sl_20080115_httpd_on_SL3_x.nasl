#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60345);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2007-3847", "CVE-2007-4465", "CVE-2007-5000", "CVE-2007-6388", "CVE-2007-6421", "CVE-2007-6422", "CVE-2008-0005");

  script_name(english:"Scientific Linux Security Update : httpd on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"A flaw was found in the mod_proxy module. On sites where a reverse
proxy is configured, a remote attacker could send a carefully crafted
request that would cause the Apache child process handling that
request to crash. On sites where a forward proxy is configured, an
attacker could cause a similar crash if a user could be persuaded to
visit a malicious site using the proxy. This could lead to a denial of
service if using a threaded Multi-Processing Module. (CVE-2007-3847)

A flaw was found in the mod_autoindex module. On sites where directory
listings are used, and the 'AddDefaultCharset' directive has been
removed from the configuration, a cross-site scripting attack might
have been possible against Web browsers which do not correctly derive
the response character set following the rules in RFC 2616.
(CVE-2007-4465)

A flaw was found in the mod_imagemap module. On sites where
mod_imagemap was enabled and an imagemap file was publicly available,
a cross-site scripting attack was possible. (CVE-2007-5000)

A flaw was found in the mod_status module. On sites where mod_status
was enabled and the status pages were publicly available, a cross-site
scripting attack was possible. (CVE-2007-6388)

A flaw was found in the mod_proxy_balancer module. On sites where
mod_proxy_balancer was enabled, a cross-site scripting attack against
an authorized user was possible. (CVE-2007-6421)

A flaw was found in the mod_proxy_balancer module. On sites where
mod_proxy_balancer was enabled, an authorized user could send a
carefully crafted request that would cause the Apache child process
handling that request to crash. This could lead to a denial of service
if using a threaded Multi-Processing Module. (CVE-2007-6422)

A flaw was found in the mod_proxy_ftp module. On sites where
mod_proxy_ftp was enabled and a forward proxy was configured, a
cross-site scripting attack was possible against Web browsers which do
not correctly derive the response character set following the rules in
RFC 2616. (CVE-2008-0005)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0801&L=scientific-linux-errata&T=0&P=979
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a5b61676"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(79, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL3", reference:"httpd-2.0.46-70.sl3")) flag++;
if (rpm_check(release:"SL3", reference:"httpd-devel-2.0.46-70.sl3")) flag++;
if (rpm_check(release:"SL3", reference:"mod_ssl-2.0.46-70.sl3")) flag++;

if (rpm_check(release:"SL4", reference:"httpd-2.0.52-38.sl4.2")) flag++;
if (rpm_check(release:"SL4", reference:"httpd-devel-2.0.52-38.sl4.2")) flag++;
if (rpm_check(release:"SL4", reference:"httpd-manual-2.0.52-38.sl4.2")) flag++;
if (rpm_check(release:"SL4", reference:"httpd-suexec-2.0.52-38.sl4.2")) flag++;
if (rpm_check(release:"SL4", reference:"mod_ssl-2.0.52-38.sl4.2")) flag++;

if (rpm_check(release:"SL5", reference:"httpd-2.2.3-11.sl5.3")) flag++;
if (rpm_check(release:"SL5", reference:"httpd-devel-2.2.3-11.sl5.3")) flag++;
if (rpm_check(release:"SL5", reference:"httpd-manual-2.2.3-11.sl5.3")) flag++;
if (rpm_check(release:"SL5", reference:"mod_ssl-2.2.3-11.sl5.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
