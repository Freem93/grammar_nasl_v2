#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(95832);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/12/15 14:46:41 $");

  script_cve_id("CVE-2016-4992", "CVE-2016-5405", "CVE-2016-5416");

  script_name(english:"Scientific Linux Security Update : 389-ds-base on SL7.x x86_64");
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
"The following packages have been upgraded to a newer upstream version:
389 -ds-base (1.3.5.10).

Security Fix(es) :

  - It was found that 389 Directory Server was vulnerable to
    a flaw in which the default ACI (Access Control
    Instructions) could be read by an anonymous user. This
    could lead to leakage of sensitive information.
    (CVE-2016-5416)

  - An information disclosure flaw was found in 389
    Directory Server. A user with no access to objects in
    certain LDAP sub-tree could send LDAP ADD operations
    with a specific object name. The error message returned
    to the user was different based on whether the target
    object existed or not. (CVE-2016-4992)

  - It was found that 389 Directory Server was vulnerable to
    a remote password disclosure via timing attack. A remote
    attacker could possibly use this flaw to retrieve
    directory server password after many tries.
    (CVE-2016-5405)

The CVE-2016-5416 issue was discovered by Viktor Ashirov (Red Hat);
the CVE-2016-4992 issue was discovered by Petr Spacek (Red Hat) and
Martin Basti (Red Hat); and the CVE-2016-5405 issue was discovered by
William Brown (Red Hat).

Additional Changes :"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1612&L=scientific-linux-errata&F=&S=&P=9692
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71d02d1e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-1.3.5.10-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-debuginfo-1.3.5.10-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-devel-1.3.5.10-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-libs-1.3.5.10-11.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-snmp-1.3.5.10-11.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
