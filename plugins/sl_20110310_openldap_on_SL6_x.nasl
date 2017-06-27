#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60988);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/06/17 13:30:50 $");

  script_cve_id("CVE-2011-1024", "CVE-2011-1025", "CVE-2011-1081");

  script_name(english:"Scientific Linux Security Update : openldap on SL6.x i386/x86_64");
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
"A flaw was found in the way OpenLDAP handled authentication failures
being passed from an OpenLDAP slave to the master. If OpenLDAP was
configured with a chain overlay and it forwarded authentication
failures, OpenLDAP would bind to the directory as an anonymous user
and return success, rather than return failure on the authenticated
bind. This could allow a user on a system that uses LDAP for
authentication to log into a directory-based account without knowing
the password. (CVE-2011-1024)

It was found that the OpenLDAP back-ndb back end allowed successful
authentication to the root distinguished name (DN) when any string was
provided as a password. A remote user could use this flaw to access an
OpenLDAP directory if they knew the value of the root DN. Note: This
issue only affected OpenLDAP installations using the NDB back-end,
which is only available for Scientific Linux 6 via third-party
software. (CVE-2011-1025)

A flaw was found in the way OpenLDAP handled modify relative
distinguished name (modrdn) requests. A remote, unauthenticated user
could use this flaw to crash an OpenLDAP server via a modrdn request
containing an empty old RDN value. (CVE-2011-1081)

After installing this update, the OpenLDAP daemons will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1103&L=scientific-linux-errata&T=0&P=8784
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?44ca3e8d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (rpm_exists(rpm:"compat-openldap-2.4", release:"SL6") && rpm_check(release:"SL6", reference:"compat-openldap-2.4.19_2.3.43-15.el6_0.2")) flag++;
if (rpm_check(release:"SL6", reference:"openldap-2.4.19-15.el6_0.2")) flag++;
if (rpm_check(release:"SL6", reference:"openldap-clients-2.4.19-15.el6_0.2")) flag++;
if (rpm_check(release:"SL6", reference:"openldap-devel-2.4.19-15.el6_0.2")) flag++;
if (rpm_check(release:"SL6", reference:"openldap-servers-2.4.19-15.el6_0.2")) flag++;
if (rpm_check(release:"SL6", reference:"openldap-servers-sql-2.4.19-15.el6_0.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
