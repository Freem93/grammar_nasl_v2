#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(92581);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/27 14:39:36 $");

  script_cve_id("CVE-2016-2119");

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

  - A flaw was found in the way Samba initiated signed
    DCE/RPC connections. A man-in-the-middle attacker could
    use this flaw to downgrade the connection to not use
    signing and therefore impersonate the server.
    (CVE-2016-2119)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1607&L=scientific-linux-errata&F=&S=&P=11905
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bf514b6f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/27");
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
if (rpm_check(release:"SL6", reference:"samba4-4.2.10-7.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-client-4.2.10-7.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-common-4.2.10-7.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-dc-4.2.10-7.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-dc-libs-4.2.10-7.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-debuginfo-4.2.10-7.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-devel-4.2.10-7.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-libs-4.2.10-7.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-pidl-4.2.10-7.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-python-4.2.10-7.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-test-4.2.10-7.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-winbind-4.2.10-7.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-winbind-clients-4.2.10-7.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"samba4-winbind-krb5-locator-4.2.10-7.el6_8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
