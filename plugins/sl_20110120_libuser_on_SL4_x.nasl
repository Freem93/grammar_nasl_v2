#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60941);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:55 $");

  script_cve_id("CVE-2011-0002");

  script_name(english:"Scientific Linux Security Update : libuser on SL4.x, SL5.x i386/x86_64");
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
"It was discovered that libuser did not set the password entry
correctly when creating LDAP (Lightweight Directory Access Protocol)
users. If an administrator did not assign a password to an LDAP based
user account, either at account creation with luseradd, or with
lpasswd after account creation, an attacker could use this flaw to log
into that account with a default password string that should have been
rejected. (CVE-2011-0002)

Note: LDAP administrators that have used libuser tools to add users
should check existing user accounts for plain text passwords, and
reset them as necessary."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1101&L=scientific-linux-errata&T=0&P=1027
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?54096be8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libuser and / or libuser-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"libuser-0.52.5-1.1.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"libuser-devel-0.52.5-1.1.el4_8.1")) flag++;

if (rpm_check(release:"SL5", reference:"libuser-0.54.7-2.1.el5_5.2")) flag++;
if (rpm_check(release:"SL5", reference:"libuser-devel-0.54.7-2.1.el5_5.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
