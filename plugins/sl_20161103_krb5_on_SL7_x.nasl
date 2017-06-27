#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(95842);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2016/12/19 15:55:08 $");

  script_cve_id("CVE-2016-3119", "CVE-2016-3120");
  script_xref(name:"IAVB", value:"2016-B-0115");

  script_name(english:"Scientific Linux Security Update : krb5 on SL7.x x86_64");
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
krb5 (1.14.1).

Security Fix(es) :

  - A NULL pointer dereference flaw was found in MIT
    Kerberos kadmind service. An authenticated attacker with
    permission to modify a principal entry could use this
    flaw to cause kadmind to dereference a NULL pointer and
    crash by supplying an empty DB argument to the
    modify_principal command, if kadmind was configured to
    use the LDAP KDB module. (CVE-2016-3119)

  - A NULL pointer dereference flaw was found in MIT
    Kerberos krb5kdc service. An authenticated attacker
    could use this flaw to cause krb5kdc to dereference a
    NULL pointer and crash by making an S4U2Self request, if
    the restrict_anonymous_to_tgt option was set to true.
    (CVE-2016-3120)

Additional Changes :"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1612&L=scientific-linux-errata&F=&S=&P=5972
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a29f143"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/15");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-debuginfo-1.14.1-26.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-devel-1.14.1-26.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-libs-1.14.1-26.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-pkinit-1.14.1-26.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-server-1.14.1-26.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-server-ldap-1.14.1-26.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"krb5-workstation-1.14.1-26.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libkadm5-1.14.1-26.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
