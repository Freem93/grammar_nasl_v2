#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(99224);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/06 13:23:47 $");

  script_cve_id("CVE-2016-2125", "CVE-2016-2126");

  script_name(english:"Scientific Linux Security Update : samba4 on SL6.x i386/x86_64");
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

  - It was found that Samba always requested forwardable
    tickets when using Kerberos authentication. A service to
    which Samba authenticated using Kerberos could
    subsequently use the ticket to impersonate Samba to
    other services or domain users. (CVE-2016-2125)

  - A flaw was found in the way Samba handled PAC (Privilege
    Attribute Certificate) checksums. A remote,
    authenticated attacker could use this flaw to crash the
    winbindd process. (CVE-2016-2126)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1704&L=scientific-linux-errata&F=&S=&P=4167
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f9859b2c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/06");
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
if (rpm_check(release:"SL6", reference:"samba4-4.2.10-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-client-4.2.10-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-common-4.2.10-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-dc-4.2.10-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-dc-libs-4.2.10-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-debuginfo-4.2.10-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-devel-4.2.10-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-libs-4.2.10-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-pidl-4.2.10-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-python-4.2.10-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-test-4.2.10-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-winbind-4.2.10-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-winbind-clients-4.2.10-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-winbind-krb5-locator-4.2.10-9.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
