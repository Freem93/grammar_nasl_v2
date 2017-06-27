#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61314);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/02/28 11:42:29 $");

  script_cve_id("CVE-2012-2134");

  script_name(english:"Scientific Linux Security Update : bind-dyndb-ldap on SL6.x i386/x86_64");
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
"The dynamic LDAP back end is a plug-in for BIND that provides back-end
capabilities to LDAP databases. It features support for dynamic
updates and internal caching that help to reduce the load on LDAP
servers.

A flaw was found in the way bind-dyndb-ldap handled LDAP query errors.
If a remote attacker were able to send DNS queries to a named server
that is configured to use bind-dyndb-ldap, they could trigger such an
error with a DNS query leveraging bind-dyndb-ldap's insufficient
escaping of the LDAP base DN (distinguished name). This would result
in an invalid LDAP query that named would retry in a loop, preventing
it from responding to other DNS queries. With this update,
bind-dyndb-ldap only attempts to retry one time when an LDAP search
returns an unexpected error. (CVE-2012-2134)

All bind-dyndb-ldap users should upgrade to this updated package,
which contains a backported patch to correct this issue. For the
update to take effect, the named service must be restarted."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1205&L=scientific-linux-errata&T=0&P=834
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e15383ea"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected bind-dyndb-ldap and / or bind-dyndb-ldap-debuginfo
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/21");
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
if (rpm_check(release:"SL6", reference:"bind-dyndb-ldap-0.2.0-7.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"bind-dyndb-ldap-debuginfo-0.2.0-7.el6_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
