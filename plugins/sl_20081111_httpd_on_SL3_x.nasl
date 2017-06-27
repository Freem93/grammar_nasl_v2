#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60493);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2008-2364", "CVE-2008-2939");

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
"A flaw was found in the mod_proxy Apache module. An attacker in
control of a Web server to which requests were being proxied could
have caused a limited denial of service due to CPU consumption and
stack exhaustion. (CVE-2008-2364)

A flaw was found in the mod_proxy_ftp Apache module. If Apache was
configured to support FTP-over-HTTP proxying, a remote attacker could
have performed a cross-site scripting attack. (CVE-2008-2939)

In addition, these updated packages fix a bug found in the handling of
the 'ProxyRemoteMatch' directive in the Scientific Linux 4 httpd
packages. This bug is not present in the Scientific Linux 3 or
Scientific Linux 5 packages."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0811&L=scientific-linux-errata&T=0&P=1054
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cccf994e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(79, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/11");
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
if (rpm_check(release:"SL3", reference:"httpd-2.0.46-71.sl3")) flag++;
if (rpm_check(release:"SL3", reference:"httpd-devel-2.0.46-71.sl3")) flag++;
if (rpm_check(release:"SL3", reference:"mod_ssl-2.0.46-71.sl3")) flag++;

if (rpm_check(release:"SL4", reference:"httpd-2.0.52-41.sl4.2")) flag++;
if (rpm_check(release:"SL4", reference:"httpd-devel-2.0.52-41.sl4.2")) flag++;
if (rpm_check(release:"SL4", reference:"httpd-manual-2.0.52-41.sl4.2")) flag++;
if (rpm_check(release:"SL4", reference:"httpd-suexec-2.0.52-41.sl4.2")) flag++;
if (rpm_check(release:"SL4", reference:"mod_ssl-2.0.52-41.sl4.2")) flag++;

if (rpm_check(release:"SL5", reference:"httpd-2.2.3-11.sl5.4")) flag++;
if (rpm_check(release:"SL5", reference:"httpd-devel-2.2.3-11.sl5.4")) flag++;
if (rpm_check(release:"SL5", reference:"httpd-manual-2.2.3-11.sl5.4")) flag++;
if (rpm_check(release:"SL5", reference:"mod_ssl-2.2.3-11.sl5.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
