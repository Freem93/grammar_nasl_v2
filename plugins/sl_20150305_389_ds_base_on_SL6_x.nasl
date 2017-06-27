#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(81751);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/03/12 14:23:03 $");

  script_cve_id("CVE-2014-8105");

  script_name(english:"Scientific Linux Security Update : 389-ds-base on SL6.x i386/x86_64");
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
"An information disclosure flaw was found in the way the 389 Directory
Server stored information in the Changelog that is exposed via the
'cn=changelog' LDAP sub-tree. An unauthenticated user could in certain
cases use this flaw to read data from the Changelog, which could
include sensitive information such as plain-text passwords.
(CVE-2014-8105)

This update also fixes the following bugs :

  - In multi-master replication (MMR), deleting a
    single-valued attribute of a Directory Server (DS) entry
    was previously in some cases not correctly replicated.
    Consequently, the entry state in the replica systems did
    not reflect the intended changes. This bug has been
    fixed and the removal of a single-valued attribute is
    now properly replicated.

  - Prior to this update, the Directory Server (DS) always
    checked the ACI syntax. As a consequence, removing an
    ACI failed with a syntax error. With this update, the
    ACI check is stopped when the ACI is going to be
    removed, and the removal thus works as expected.

In addition, this update adds the following enhancement :

  - The buffer size limit for the 389-ds-base application
    has been increased to 2MB in order to match the buffer
    size limit of Simple Authentication and Security Layer
    (SASL) and Basic Encoding Rules (BER).

After installing this update, the 389 server service will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1503&L=scientific-linux-errata&T=0&P=414
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0736161d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"389-ds-base-1.2.11.15-50.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"389-ds-base-debuginfo-1.2.11.15-50.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"389-ds-base-devel-1.2.11.15-50.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"389-ds-base-libs-1.2.11.15-50.el6_6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
