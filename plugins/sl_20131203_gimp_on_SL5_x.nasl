#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(71303);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/06 13:24:15 $");

  script_cve_id("CVE-2012-5576", "CVE-2013-1913", "CVE-2013-1978");

  script_name(english:"Scientific Linux Security Update : gimp on SL5.x, SL6.x i386/x86_64");
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
"A stack-based buffer overflow flaw, a heap-based buffer overflow, and
an integer overflow flaw were found in the way GIMP loaded certain X
Window System (XWD) image dump files. A remote attacker could provide
a specially crafted XWD image file that, when processed, would cause
the XWD plug-in to crash or, potentially, execute arbitrary code with
the privileges of the user running the GIMP. (CVE-2012-5576,
CVE-2013-1913, CVE-2013-1978)

The GIMP must be restarted for the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1312&L=scientific-linux-errata&T=0&P=1925
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db8209f9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"gimp-2.2.13-3.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"gimp-debuginfo-2.2.13-3.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"gimp-devel-2.2.13-3.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"gimp-libs-2.2.13-3.el5_10")) flag++;

if (rpm_check(release:"SL6", reference:"gimp-2.6.9-6.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"gimp-debuginfo-2.6.9-6.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"gimp-devel-2.6.9-6.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"gimp-devel-tools-2.6.9-6.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"gimp-help-browser-2.6.9-6.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"gimp-libs-2.6.9-6.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
