#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61094);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:56 $");

  script_cve_id("CVE-2010-4341");

  script_name(english:"Scientific Linux Security Update : sssd on SL5.x i386/x86_64");
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
"The System Security Services Daemon (SSSD) provides a set of daemons
to manage access to remote directories and authentication mechanisms.
It provides an NSS and PAM interface toward the system and a pluggable
back-end system to connect to multiple different account sources. It
is also the basis to provide client auditing and policy services for
projects such as FreeIPA.

A flaw was found in the SSSD PAM responder that could allow a local
attacker to force SSSD to enter an infinite loop via a
carefully-crafted packet. With SSSD unresponsive, legitimate users
could be denied the ability to log in to the system. (CVE-2010-4341)

These updated sssd packages include a number of bug fixes and
enhancements. Space precludes documenting all of these changes in this
advisory.

All sssd users are advised to upgrade to these updated sssd packages,
which upgrade SSSD to upstream version 1.5.1 to correct this issue,
and fix the bugs and add the enhancements noted in the Technical
Notes."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1108&L=scientific-linux-errata&T=0&P=2791
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5aa77913"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sssd, sssd-client and / or sssd-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"sssd-1.5.1-37.el5")) flag++;
if (rpm_check(release:"SL5", reference:"sssd-client-1.5.1-37.el5")) flag++;
if (rpm_check(release:"SL5", reference:"sssd-tools-1.5.1-37.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
