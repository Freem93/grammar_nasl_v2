#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1854. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64018);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/10 18:05:24 $");

  script_cve_id("CVE-2011-4862");
  script_xref(name:"RHSA", value:"2011:1854");

  script_name(english:"RHEL 6 : krb5-appl (RHSA-2011:1854)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5-appl packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.0 and 6.1 Extended Update
Support.

The Red Hat Security Response Team has rated this update as having
critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The krb5-appl packages provide Kerberos-aware telnet, ftp, rcp, rsh,
and rlogin clients and servers. Kerberos is a network authentication
system which allows clients and servers to authenticate to each other
using symmetric encryption and a trusted third-party, the Key
Distribution Center (KDC).

A buffer overflow flaw was found in the MIT krb5 telnet daemon
(telnetd). A remote attacker who can access the telnet port of a
target machine could use this flaw to execute arbitrary code as root.
(CVE-2011-4862)

Note that the krb5 telnet daemon is not enabled by default in any
version of Red Hat Enterprise Linux. In addition, the default firewall
rules block remote access to the telnet port. This flaw does not
affect the telnet daemon distributed in the telnet-server package.

For users who have installed the krb5-appl-servers package, have
enabled the krb5 telnet daemon, and have it accessible remotely, this
update should be applied immediately.

All krb5-appl-server users should upgrade to these updated packages,
which contain a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4862.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2011-008.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1854.html"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-appl-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-appl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:krb5-appl-servers");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"krb5-appl-clients-1.0.1-1.el6_0.1")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"krb5-appl-clients-1.0.1-1.el6_0.1")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"krb5-appl-clients-1.0.1-1.el6_0.1")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"krb5-appl-debuginfo-1.0.1-1.el6_0.1")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"krb5-appl-debuginfo-1.0.1-1.el6_0.1")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"krb5-appl-debuginfo-1.0.1-1.el6_0.1")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"krb5-appl-servers-1.0.1-1.el6_0.1")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"krb5-appl-servers-1.0.1-1.el6_0.1")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"krb5-appl-servers-1.0.1-1.el6_0.1")) flag++;

if (rpm_check(release:"RHEL6", sp:"1", cpu:"i686", reference:"krb5-appl-clients-1.0.1-2.el6_1.3")) flag++;
if (rpm_check(release:"RHEL6", sp:"1", cpu:"s390x", reference:"krb5-appl-clients-1.0.1-2.el6_1.3")) flag++;
if (rpm_check(release:"RHEL6", sp:"1", cpu:"x86_64", reference:"krb5-appl-clients-1.0.1-2.el6_1.3")) flag++;
if (rpm_check(release:"RHEL6", sp:"1", cpu:"i686", reference:"krb5-appl-debuginfo-1.0.1-2.el6_1.3")) flag++;
if (rpm_check(release:"RHEL6", sp:"1", cpu:"s390x", reference:"krb5-appl-debuginfo-1.0.1-2.el6_1.3")) flag++;
if (rpm_check(release:"RHEL6", sp:"1", cpu:"x86_64", reference:"krb5-appl-debuginfo-1.0.1-2.el6_1.3")) flag++;
if (rpm_check(release:"RHEL6", sp:"1", cpu:"i686", reference:"krb5-appl-servers-1.0.1-2.el6_1.3")) flag++;
if (rpm_check(release:"RHEL6", sp:"1", cpu:"s390x", reference:"krb5-appl-servers-1.0.1-2.el6_1.3")) flag++;
if (rpm_check(release:"RHEL6", sp:"1", cpu:"x86_64", reference:"krb5-appl-servers-1.0.1-2.el6_1.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
