#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(77553);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/09/05 11:19:55 $");

  script_cve_id("CVE-2013-4115", "CVE-2014-3609");

  script_name(english:"Scientific Linux Security Update : squid on SL5.x, SL6.x i386/x86_64");
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
"A flaw was found in the way Squid handled malformed HTTP Range
headers. A remote attacker able to send HTTP requests to the Squid
proxy could use this flaw to crash Squid. (CVE-2014-3609)

A buffer overflow flaw was found in Squid's DNS lookup module. A
remote attacker able to send HTTP requests to the Squid proxy could
use this flaw to crash Squid. (CVE-2013-4115)

After installing this update, the squid service will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1409&L=scientific-linux-errata&T=0&P=192
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?15403ed3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squid and / or squid-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/05");
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
if (rpm_check(release:"SL5", reference:"squid-2.6.STABLE21-7.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"squid-debuginfo-2.6.STABLE21-7.el5_10")) flag++;

if (rpm_check(release:"SL6", reference:"squid-3.1.10-22.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"squid-debuginfo-3.1.10-22.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
