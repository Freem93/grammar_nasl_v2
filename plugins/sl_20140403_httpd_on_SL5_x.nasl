#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(73368);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/07/26 00:30:55 $");

  script_cve_id("CVE-2013-6438", "CVE-2014-0098");

  script_name(english:"Scientific Linux Security Update : httpd on SL5.x i386/x86_64");
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
"It was found that the mod_dav module did not correctly strip leading
white space from certain elements in a parsed XML. In certain httpd
configurations that use the mod_dav module (for example when using the
mod_dav_svn module), a remote attacker could send a specially crafted
DAV request that would cause the httpd child process to crash or,
possibly, allow the attacker to execute arbitrary code with the
privileges of the 'apache' user. (CVE-2013-6438)

A buffer over-read flaw was found in the httpd mod_log_config module.
In configurations where cookie logging is enabled (on Scientific Linux
it is disabled by default), a remote attacker could use this flaw to
crash the httpd child process via an HTTP request with a malformed
cookie header. (CVE-2014-0098)

After installing the updated packages, the httpd daemon will be
restarted automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1404&L=scientific-linux-errata&T=0&P=321
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?40d1484e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"httpd-2.2.3-85.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"httpd-debuginfo-2.2.3-85.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"httpd-devel-2.2.3-85.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"httpd-manual-2.2.3-85.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"mod_ssl-2.2.3-85.el5_10")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
