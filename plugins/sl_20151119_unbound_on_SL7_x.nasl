#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(87577);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/22 15:46:34 $");

  script_cve_id("CVE-2014-8602");

  script_name(english:"Scientific Linux Security Update : unbound on SL7.x x86_64");
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
"A denial of service flaw was found in unbound that an attacker could
use to trick the unbound resolver into following an endless loop of
delegations, consuming an excessive amount of resources.
(CVE-2014-8602)

This update also fixes the following bugs :

  - Prior to this update, there was a mistake in the time
    configuration in the cron job invoking unbound-anchor to
    update the root zone key. Consequently, unbound-anchor
    was invoked once a month instead of every day, thus not
    complying with RFC 5011. The cron job has been replaced
    with a systemd timer unit that is invoked on a daily
    basis. Now, the root zone key validity is checked daily
    at a random time within a 24-hour window, and compliance
    with RFC 5011 is ensured.

  - Previously, the unbound packages were installing their
    configuration file for the systemd-tmpfiles utility into
    the /etc/tmpfiles.d/ directory. As a consequence,
    changes to unbound made by the administrator in
    /etc/tmpfiles.d/ could be overwritten on package
    reinstallation or update. To fix this bug, unbound has
    been amended to install the configuration file into the
    /usr/lib/tmpfiles.d/ directory. As a result, the system
    administrator's configuration in /etc/tmpfiles.d/ is
    preserved, including any changes, on package
    reinstallation or update.

  - The unbound server default configuration included
    validation of DNS records using the DNSSEC Look-aside
    Validation (DLV) registry. The Internet Systems
    Consortium (ISC) plans to deprecate the DLV registry
    service as no longer needed, and unbound could execute
    unnecessary steps. Therefore, the use of the DLV
    registry has been removed from the unbound server
    default configuration. Now, unbound does not try to
    perform DNS records validation using the DLV registry."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=5249
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?32eff73f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"unbound-1.4.20-26.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"unbound-debuginfo-1.4.20-26.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"unbound-devel-1.4.20-26.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"unbound-libs-1.4.20-26.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"unbound-python-1.4.20-26.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
