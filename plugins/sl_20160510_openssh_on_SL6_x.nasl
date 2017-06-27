#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(91540);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2017/04/18 13:37:17 $");

  script_cve_id("CVE-2015-5352", "CVE-2015-6563", "CVE-2015-6564", "CVE-2016-1908");

  script_name(english:"Scientific Linux Security Update : openssh on SL6.x i386/x86_64");
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
"Security Fix(es) :

  - It was found that the OpenSSH client did not properly
    enforce the ForwardX11Timeout setting. A malicious or
    compromised remote X application could possibly use this
    flaw to establish a trusted connection to the local X
    server, even if only untrusted X11 forwarding was
    requested. (CVE-2015-5352)

  - A flaw was found in the way OpenSSH handled PAM
    authentication when using privilege separation. An
    attacker with valid credentials on the system and able
    to fully compromise a non-privileged pre-authentication
    process using a different flaw could use this flaw to
    authenticate as other users. (CVE-2015-6563)

  - A use-after-free flaw was found in OpenSSH. An attacker
    able to fully compromise a non-privileged
    pre-authentication process using a different flaw could
    possibly cause sshd to crash or execute arbitrary code
    with root privileges. (CVE-2015-6564)

  - An access flaw was discovered in OpenSSH; the OpenSSH
    client did not correctly handle failures to generate
    authentication cookies for untrusted X11 forwarding. A
    malicious or compromised remote X application could
    possibly use this flaw to establish a trusted connection
    to the local X server, even if only untrusted X11
    forwarding was requested. (CVE-2016-1908)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1606&L=scientific-linux-errata&F=&S=&P=2911
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0efb7682"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"openssh-5.3p1-117.el6")) flag++;
if (rpm_check(release:"SL6", reference:"openssh-askpass-5.3p1-117.el6")) flag++;
if (rpm_check(release:"SL6", reference:"openssh-clients-5.3p1-117.el6")) flag++;
if (rpm_check(release:"SL6", reference:"openssh-debuginfo-5.3p1-117.el6")) flag++;
if (rpm_check(release:"SL6", reference:"openssh-ldap-5.3p1-117.el6")) flag++;
if (rpm_check(release:"SL6", reference:"openssh-server-5.3p1-117.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pam_ssh_agent_auth-0.9.3-117.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
