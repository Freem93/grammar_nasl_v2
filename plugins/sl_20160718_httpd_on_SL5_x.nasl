#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(92403);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/01/16 16:05:34 $");

  script_cve_id("CVE-2016-5387");
  script_xref(name:"IAVA", value:"2017-A-0010");

  script_name(english:"Scientific Linux Security Update : httpd on SL5.x, SL6.x i386/x86_64 (httpoxy)");
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
"Security Fix(es) :

  - It was discovered that httpd used the value of the Proxy
    header from HTTP requests to initialize the HTTP_PROXY
    environment variable for CGI scripts, which in turn was
    incorrectly used by certain HTTP client implementations
    to configure the proxy for outgoing HTTP requests. A
    remote attacker could possibly use this flaw to redirect
    HTTP requests performed by a CGI script to an
    attacker-controlled proxy via a malicious HTTP request.
    (CVE-2016-5387)

Note: After this update, httpd will no longer pass the value of the
Proxy request header to scripts via the HTTP_PROXY environment
variable."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1607&L=scientific-linux-errata&F=&S=&P=6086
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d084ac2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"httpd-2.2.3-92.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"httpd-debuginfo-2.2.3-92.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"httpd-devel-2.2.3-92.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"httpd-manual-2.2.3-92.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"mod_ssl-2.2.3-92.el5_11")) flag++;

if (rpm_check(release:"SL6", reference:"httpd-2.2.15-54.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"httpd-debuginfo-2.2.15-54.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"httpd-devel-2.2.15-54.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"httpd-manual-2.2.15-54.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"httpd-tools-2.2.15-54.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"mod_ssl-2.2.15-54.el6_8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
