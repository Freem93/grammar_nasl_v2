#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60279);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:52 $");

  script_cve_id("CVE-2007-4351");

  script_name(english:"Scientific Linux Security Update : cups on SL5.x i386/x86_64");
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
"A flaw was found in the way CUPS handles certain Internet Printing
Protocol (IPP) tags. A remote attacker who is able to connect to the
IPP TCP port could send a malicious request causing the CUPS daemon to
crash, or potentially execute arbitrary code. Please note that the
default CUPS configuration does not allow remote hosts to connect to
the IPP TCP port. (CVE-2007-4351)

In addition, the following bugs were fixed :

  - the CUPS service has been changed to start after sshd,
    to avoid causing delays when logging in when the system
    is booted.

  - the logrotate settings have been adjusted so they do not
    cause CUPS to reload its configuration. This is to avoid
    re-printing the current job, which could occur when it
    was a long-running job.

  - a bug has been fixed in the handling of the
    If-Modified-Since: HTTP header.

  - in the LSPP configuration, labels for labeled jobs did
    not line-wrap. This has been fixed.

  - an access check in the LSPP configuration has been made
    more secure.

  - the cups-lpd service no longer ignores the
    '-odocument-format=...' option.

  - a memory allocation bug has been fixed in cupsd.

  - support for UNIX domain sockets authentication without
    passwords has been added.

  - in the LSPP configuration, a problem that could lead to
    cupsd crashing has been fixed.

  - the error handling in the initscript has been improved.

  - The job-originating-host-name attribute was not
    correctly set for jobs submitted via the cups-lpd
    service. This has been fixed.

  - a problem with parsing IPv6 addresses in the
    configuration file has been fixed.

  - a problem that could lead to cupsd crashing when it
    failed to open a 'file:' URI has been fixed."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0710&L=scientific-linux-errata&T=0&P=2674
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e2c02f19"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/31");
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
if (rpm_check(release:"SL5", reference:"cups-1.2.4-11.14.el5.1")) flag++;
if (rpm_check(release:"SL5", reference:"cups-devel-1.2.4-11.14.el5.1")) flag++;
if (rpm_check(release:"SL5", reference:"cups-libs-1.2.4-11.14.el5.1")) flag++;
if (rpm_check(release:"SL5", reference:"cups-lpd-1.2.4-11.14.el5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
