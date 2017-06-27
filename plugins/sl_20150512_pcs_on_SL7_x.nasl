#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(83454);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/05/18 13:48:31 $");

  script_cve_id("CVE-2015-1848");

  script_name(english:"Scientific Linux Security Update : pcs on SL7.x x86_64");
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
"It was found that the pcs daemon did not sign cookies containing
session data that were sent to clients connecting via the pcsd web UI.
A remote attacker could use this flaw to forge cookies and bypass
authorization checks, possibly gaining elevated privileges in the pcsd
web UI. (CVE-2015-1848)

This update also fixes the following bug :

  - Previously, the Corosync tool allowed the two_node
    option and the auto_tie_breaker option to exist in the
    corosync.conf file at the same time. As a consequence,
    if both options were included, auto_tie_breaker was
    silently ignored and the two_node fence race decided
    which node would survive in the event of a communication
    break. With this update, the pcs daemon has been fixed
    so that it does not produce corosync.conf files with
    both two_node and auto_tie_breaker included. In
    addition, if both two_node and auto_tie_breaker are
    detected in corosync.conf, Corosync issues a message at
    start-up and disables two_node mode. As a result,
    auto_tie_breaker effectively overrides two_node mode if
    both options are specified.

After installing the updated packages, the pcsd daemon will be
restarted automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1505&L=scientific-linux-errata&T=0&P=1491
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8c579365"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected pcs, pcs-debuginfo and / or python-clufter
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcs-0.9.137-13.el7_1.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"pcs-debuginfo-0.9.137-13.el7_1.2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-clufter-0.9.137-13.el7_1.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
