#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61213);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/06/16 11:00:59 $");

  script_cve_id("CVE-2011-4862");

  script_name(english:"Scientific Linux Security Update : krb5-appl on SL6.x i386/x86_64");
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
"The krb5-appl packages provide Kerberos-aware telnet, ftp, rcp, rsh,
and rlogin clients and servers. Kerberos is a network authentication
system which allows clients and servers to authenticate to each other
using symmetric encryption and a trusted third party, the Key
Distribution Center (KDC).

A buffer overflow flaw was found in the MIT krb5 telnet daemon
(telnetd). A remote attacker who can access the telnet port of a
target machine could use this flaw to execute arbitrary code as root.
(CVE-2011-4862)

Note that the krb5 telnet daemon is not enabled by default in any
version of Scientific Linux. In addition, the default firewall rules
block remote access to the telnet port. This flaw does not affect the
telnet daemon distributed in the telnet-server package.

For users who have installed the krb5-appl-servers package, have
enabled the krb5 telnet daemon, and have it accessible remotely, this
update should be applied immediately.

All krb5-appl-server users should upgrade to these updated packages,
which contain a backported patch to correct this issue."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1112&L=scientific-linux-errata&T=0&P=4434
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33d58d3f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected krb5-appl-clients, krb5-appl-debuginfo and / or
krb5-appl-servers packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-760");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux BSD-derived Telnet Service Encryption Key ID Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"krb5-appl-clients-1.0.1-7.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-appl-debuginfo-1.0.1-7.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"krb5-appl-servers-1.0.1-7.el6_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
