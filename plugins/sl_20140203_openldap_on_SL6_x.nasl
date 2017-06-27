#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(72276);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/02/07 11:46:01 $");

  script_cve_id("CVE-2013-4449");

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
"A denial of service flaw was found in the way the OpenLDAP server
daemon (slapd) performed reference counting when using the rwm
(rewrite/remap) overlay. A remote attacker able to query the OpenLDAP
server could use this flaw to crash the server by immediately
unbinding from the server after sending a search request.
(CVE-2013-4449)

This update also fixes the following bug :

  - Previously, OpenLDAP did not properly handle a number of
    simultaneous updates. As a consequence, sending a number
    of parallel update requests to the server could cause a
    deadlock. With this update, a superfluous locking
    mechanism causing the deadlock has been removed, thus
    fixing the bug."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1402&L=scientific-linux-errata&T=0&P=203
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?971b6e04"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"openldap-2.4.23-34.el6_5.1")) flag++;
if (rpm_check(release:"SL6", reference:"openldap-clients-2.4.23-34.el6_5.1")) flag++;
if (rpm_check(release:"SL6", reference:"openldap-debuginfo-2.4.23-34.el6_5.1")) flag++;
if (rpm_check(release:"SL6", reference:"openldap-devel-2.4.23-34.el6_5.1")) flag++;
if (rpm_check(release:"SL6", reference:"openldap-servers-2.4.23-34.el6_5.1")) flag++;
if (rpm_check(release:"SL6", reference:"openldap-servers-sql-2.4.23-34.el6_5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
