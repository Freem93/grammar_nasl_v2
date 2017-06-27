#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60217);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/07/20 01:56:57 $");

  script_cve_id("CVE-2006-5752", "CVE-2007-1863", "CVE-2007-3304");

  script_name(english:"Scientific Linux Security Update : httpd on SL5.x, SL4.x i386/x86_64");
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
"The Apache HTTP Server did not verify that a process was an Apache
child process before sending it signals. A local attacker with the
ability to run scripts on the Apache HTTP Server could manipulate the
scoreboard and cause arbitrary processes to be terminated which could
lead to a denial of service (CVE-2007-3304). This issue is not
exploitable on Scientific Linux 5 if using the default SELinux
targeted policy.

A flaw was found in the Apache HTTP Server mod_status module. On sites
where the server-status page is publicly accessible and ExtendedStatus
is enabled this could lead to a cross-site scripting attack. On
Scientific Linux the server-status page is not enabled by default and
it is best practice to not make this publicly available.
(CVE-2006-5752)

A bug was found in the Apache HTTP Server mod_cache module. On sites
where caching is enabled, a remote attacker could send a carefully
crafted request that would cause the Apache child process handling
that request to crash. This could lead to a denial of service if using
a threaded Multi-Processing Module. (CVE-2007-1863)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0706&L=scientific-linux-errata&T=0&P=4157
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0774127f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"httpd-2.0.52-32.2.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"httpd-devel-2.0.52-32.2.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"httpd-manual-2.0.52-32.2.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"httpd-suexec-2.0.52-32.2.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"mod_ssl-2.0.52-32.2.sl4")) flag++;

if (rpm_check(release:"SL5", reference:"httpd-2.2.3-7.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"httpd-devel-2.2.3-7.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"httpd-manual-2.2.3-7.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"mod_ssl-2.2.3-7.sl5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
