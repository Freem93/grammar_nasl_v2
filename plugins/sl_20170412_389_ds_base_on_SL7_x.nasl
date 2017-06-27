#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(99349);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/13 13:33:09 $");

  script_cve_id("CVE-2017-2668");

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
"Security Fix(es) :

  - An invalid pointer dereference flaw was found in the way
    389-ds-base handled LDAP bind requests. A remote
    unauthenticated attacker could use this flaw to make
    ns-slapd crash via a specially crafted LDAP bind
    request, resulting in denial of service. (CVE-2017-2668)

Bug Fix(es) :

  - Previously, when adding a filtered role definition that
    uses the 'nsrole' virtual attribute in the filter,
    Directory Server terminated unexpectedly. A patch has
    been applied, and now the roles plug-in ignores all
    virtual attributes. As a result, an error message is
    logged when an invalid filter is used. Additionally, the
    role is deactivated and Directory Server no longer
    fails.

  - In a replication topology, Directory Server incorrectly
    calculated the size of string format entries when a lot
    of entries were deleted. The calculated size of entries
    was smaller than the actual required size. Consequently,
    Directory Server allocated insufficient memory and
    terminated unexpectedly when the data was written to it.
    With this update, the size of string format entries is
    now calculated correctly in the described situation and
    Directory Server no longer terminates unexpectedly."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1704&L=scientific-linux-errata&F=&S=&P=8154
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d7cea4a7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-1.3.5.10-20.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-debuginfo-1.3.5.10-20.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-devel-1.3.5.10-20.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-libs-1.3.5.10-20.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-snmp-1.3.5.10-20.el7_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
