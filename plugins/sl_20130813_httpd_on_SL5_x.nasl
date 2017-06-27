#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(69342);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/09/15 00:18:57 $");

  script_cve_id("CVE-2013-1896");

  script_name(english:"Scientific Linux Security Update : httpd on SL5.x, SL6.x i386/x86_64");
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
"A flaw was found in the way the mod_dav module of the Apache HTTP
Server handled merge requests. An attacker could use this flaw to send
a crafted merge request that contains URIs that are not configured for
DAV, causing the httpd child process to crash. (CVE-2013-1896)

After installing the updated packages, the httpd daemon will be
restarted automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1308&L=scientific-linux-errata&T=0&P=977
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?04236bcb"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"httpd-2.2.3-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"httpd-debuginfo-2.2.3-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"httpd-devel-2.2.3-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"httpd-manual-2.2.3-82.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"mod_ssl-2.2.3-82.sl5")) flag++;

if (rpm_check(release:"SL6", reference:"httpd-2.2.15-29.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"httpd-debuginfo-2.2.15-29.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"httpd-devel-2.2.15-29.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"httpd-manual-2.2.15-29.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"httpd-tools-2.2.15-29.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"mod_ssl-2.2.15-29.sl6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
