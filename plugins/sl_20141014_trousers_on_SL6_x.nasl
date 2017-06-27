#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(78642);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/10/23 10:48:28 $");

  script_cve_id("CVE-2012-0698");

  script_name(english:"Scientific Linux Security Update : trousers on SL6.x i386/x86_64");
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
"A flaw was found in the way tcsd, the daemon that manages Trusted
Computing resources, processed incoming TCP packets. A remote attacker
could send a specially crafted TCP packet that, when processed by
tcsd, could cause the daemon to crash. Note that by default tcsd
accepts requests on localhost only. (CVE-2012-0698)

The trousers package has been upgraded to upstream version 0.3.13,
which provides a number of bug fixes and enhancements over the
previous version, including corrected internal symbol names to avoid
collisions with other applications, fixed memory leaks, added IPv6
support, fixed buffer handling in tcsd, as well as changed the license
to BSD."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1410&L=scientific-linux-errata&T=0&P=1572
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d2e00530"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/23");
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
if (rpm_check(release:"SL6", reference:"trousers-0.3.13-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"trousers-debuginfo-0.3.13-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"trousers-devel-0.3.13-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"trousers-static-0.3.13-2.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
