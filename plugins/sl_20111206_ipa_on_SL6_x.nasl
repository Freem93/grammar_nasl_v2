#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61188);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2011-3636");

  script_name(english:"Scientific Linux Security Update : ipa on SL6.x i386/x86_64");
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
"This Identity Management Application is a centralized authentication,
identity management and authorization solution for both traditional
and cloud based enterprise environments. It integrates components of
the Upstream Directory Server, MIT Kerberos, the Upstream Certificate
System, NTP, and DNS. It provides web browser and command-line
interfaces. Its administration tools allow an administrator to quickly
install, set up, and administer a group of domain controllers to meet
the authentication and identity management requirements of large scale
Linux and UNIX deployments.

A Cross-Site Request Forgery (CSRF) flaw was found in this package. If
a remote attacker could trick a user, who was logged into the
management web interface, into visiting a specially crafted URL, the
attacker could perform configuration changes with the privileges of
the logged in user. (CVE-2011-3636)

Due to the changes required to fix CVE-2011-3636, client tools will
need to be updated for client systems to communicate with updated
servers. New client systems will need to have the updated ipa-client
package installed to be enrolled. Already enrolled client systems will
need to have the updated certmonger package installed to be able to
renew their system certificate. Note that system certificates are
valid for two years by default.

This update includes several bug fixes. Space precludes documenting
all of these changes in this advisory.

Users of this software should upgrade to these updated packages, which
correct these issues.

A number of additional packages were added to the security repository
so that this package could be installed on older SL systems."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1201&L=scientific-linux-errata&T=0&P=319
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?18ca00f6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/06");
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
if (rpm_check(release:"SL6", reference:"ipa-admintools-2.1.3-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ipa-client-2.1.3-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ipa-debuginfo-2.1.3-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ipa-python-2.1.3-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ipa-server-2.1.3-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ipa-server-selinux-2.1.3-9.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
