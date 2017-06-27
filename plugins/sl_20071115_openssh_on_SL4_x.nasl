#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60306);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:52 $");

  script_cve_id("CVE-2006-5052", "CVE-2007-3102");

  script_name(english:"Scientific Linux Security Update : openssh on SL4.x i386/x86_64");
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
"A flaw was found in the way the ssh server wrote account names to the
audit subsystem. An attacker could inject strings containing parts of
audit messages which could possibly mislead or confuse audit log
parsing tools. (CVE-2007-3102)

A flaw was found in the way the OpenSSH server processes GSSAPI
authentication requests. When GSSAPI authentication was enabled in
OpenSSH server, a remote attacker may have been able to determine if a
username is valid. (CVE-2006-5052)

The following bugs were also fixed :

  - the ssh daemon did not generate audit messages when an
    ssh session was closed.

  - GSSAPI authentication sometimes failed on clusters using
    DNS or load-balancing.

  - the sftp client and server leaked small amounts of
    memory in some cases.

  - the sftp client didn't properly exit and return non-zero
    status in batch mode when the destination disk drive was
    full.

  - when restarting the ssh daemon with the initscript, the
    ssh daemon was sometimes not restarted successfully
    because the old running ssh daemon was not properly
    killed.

  - with challenge/response authentication enabled, the pam
    sub-process was not terminated if the user
    authentication timed out."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0711&L=scientific-linux-errata&T=0&P=3964
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2d7292f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/15");
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
if (rpm_check(release:"SL4", reference:"openssh-3.9p1-8.RHEL4.24")) flag++;
if (rpm_check(release:"SL4", reference:"openssh-askpass-3.9p1-8.RHEL4.24")) flag++;
if (rpm_check(release:"SL4", reference:"openssh-askpass-gnome-3.9p1-8.RHEL4.24")) flag++;
if (rpm_check(release:"SL4", reference:"openssh-clients-3.9p1-8.RHEL4.24")) flag++;
if (rpm_check(release:"SL4", reference:"openssh-server-3.9p1-8.RHEL4.24")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
