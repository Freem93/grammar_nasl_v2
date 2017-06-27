#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(65627);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/03/24 23:40:37 $");

  script_cve_id("CVE-2013-0287");

  script_name(english:"Scientific Linux Security Update : sssd on SL6.x i386/x86_64");
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
"When SSSD was configured as a Microsoft Active Directory client by
using the new Active Directory provider (introduced in
SLSA-2013:0508), the Simple Access Provider ('access_provider =
simple' in '/etc/sssd/sssd.conf') did not handle access control
correctly. If any groups were specified with the 'simple_deny_groups'
option (in sssd.conf), all users were permitted access.
(CVE-2013-0287)

This update also fixes the following bugs :

  - If a group contained a member whose Distinguished Name
    (DN) pointed out of any of the configured search bases,
    the search request that was processing this particular
    group never ran to completion. To the user, this bug
    manifested as a long timeout between requesting the
    group data and receiving the result. A patch has been
    provided to address this bug and SSSD now processes
    group search requests without delays.

  - The pwd_expiration_warning should have been set for
    seven days, but instead it was set to zero for Kerberos.
    This incorrect zero setting returned the 'always display
    warning if the server sends one' error message and users
    experienced problems in environments like IPA or Active
    Directory. Currently, the value setting for Kerberos is
    modified and this issue no longer occurs."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1303&L=scientific-linux-errata&T=0&P=5274
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?05664cac"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"libipa_hbac-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"libipa_hbac-devel-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"libipa_hbac-python-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"libsss_autofs-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"libsss_idmap-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"libsss_idmap-devel-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"libsss_sudo-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"libsss_sudo-devel-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-client-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-debuginfo-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"sssd-tools-1.9.2-82.4.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
