#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(76246);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/26 11:29:48 $");

  script_cve_id("CVE-2014-0240", "CVE-2014-0242");

  script_name(english:"Scientific Linux Security Update : mod_wsgi on SL6.x i386/srpm/x86_64");
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
"It was found that mod_wsgi did not properly drop privileges if the
call to setuid() failed. If mod_wsgi was set up to allow unprivileged
users to run WSGI applications, a local user able to run a WSGI
application could possibly use this flaw to escalate their privileges
on the system. (CVE-2014-0240)

Note: mod_wsgi is not intended to provide privilege separation for
WSGI applications. Systems relying on mod_wsgi to limit or sandbox the
privileges of mod_wsgi applications should migrate to a different
solution with proper privilege separation.

It was discovered that mod_wsgi could leak memory of a hosted web
application via the 'Content-Type' header. A remote attacker could
possibly use this flaw to disclose limited portions of the web
application's memory. (CVE-2014-0242)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1406&L=scientific-linux-errata&T=0&P=2620
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a0ddf8f7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mod_wsgi and / or mod_wsgi-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/26");
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
if (rpm_check(release:"SL6", reference:"mod_wsgi-3.2-6.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"mod_wsgi-debuginfo-3.2-6.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
