#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60296);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:52 $");

  script_cve_id("CVE-2006-5052", "CVE-2007-3102");

  script_name(english:"Scientific Linux Security Update : openssh on SL5.x");
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
"Problem description :

A flaw was found in the way the ssh server wrote account names to the
audit subsystem. An attacker could inject strings containing parts of
audit messages, which could possibly mislead or confuse audit log
parsing tools. (CVE-2007-3102)

A flaw was found in the way the OpenSSH server processes GSSAPI
authentication requests. When GSSAPI authentication was enabled in the
OpenSSH server, a remote attacker was potentially able to determine if
a username is valid. (CVE-2006-5052)

The following bugs in SELinux MLS (Multi-Level Security) support has
also been fixed in this update :

  - It was sometimes not possible to select a SELinux role
    and level when logging in using ssh.

  - If the user obtained a non-default SELinux role or
    level, the role change was not recorded in the audit
    subsystem.

  - In some cases, on labeled networks, sshd allowed logins
    from level ranges it should not allow.

The updated packages also contain experimental support for using
private keys stored in PKCS#11 tokens for client authentication. The
support is provided through the NSS (Network Security Services)
library."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0711&L=scientific-linux-errata&T=0&P=884
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?be000e7c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

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
if (rpm_check(release:"SL5", reference:"openssh-4.3p2-24.el5")) flag++;
if (rpm_check(release:"SL5", reference:"openssh-askpass-4.3p2-24.el5")) flag++;
if (rpm_check(release:"SL5", reference:"openssh-clients-4.3p2-24.el5")) flag++;
if (rpm_check(release:"SL5", reference:"openssh-server-4.3p2-24.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
