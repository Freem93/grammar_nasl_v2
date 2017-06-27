#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(82293);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/01 13:32:21 $");

  script_cve_id("CVE-2015-0283", "CVE-2015-1827");

  script_name(english:"Scientific Linux Security Update : ipa and slapi-nis on SL7.x x86_64");
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
"The ipa component provides centrally managed Identity, Policy, and
Audit. The slapi-nis component provides NIS Server and Schema
Compatibility plug- ins for Directory Server.

It was discovered that the IPA extdom Directory Server plug-in did not
correctly perform memory reallocation when handling user account
information. A request for a list of groups for a user that belongs to
a large number of groups would cause a Directory Server to crash.
(CVE-2015-1827)

It was discovered that the slapi-nis Directory Server plug-in did not
correctly perform memory reallocation when handling user account
information. A request for information about a group with many
members, or a request for a user that belongs to a large number of
groups, would cause a Directory Server to enter an infinite loop and
consume an excessive amount of CPU time. (CVE-2015-0283)

This update fixes the following bugs :

  - Previously, users of IdM were not properly granted the
    default permission to read the
    'facsimiletelephonenumber' user attribute. This update
    adds 'facsimiletelephonenumber' to the Access Control
    Instruction (ACI) for user data, which makes the
    attribute readable to authenticated users as expected.

  - Prior to this update, when a DNS zone was saved in an
    LDAP database without a dot character (.) at the end,
    internal DNS commands and operations, such as
    dnsrecord-* or dnszone-*, failed. With this update, DNS
    commands always supply the DNS zone with a dot character
    at the end, which prevents the described problem.

  - After a full-server IdM restore operation, the restored
    server in some cases contained invalid data. In
    addition, if the restored server was used to
    reinitialize a replica, the replica then contained
    invalid data as well. To fix this problem, the IdM API
    is now created correctly during the restore operation,
    and *.ldif files are not skipped during the removal of
    RUV data. As a result, the restored server and its
    replica no longer contain invalid data.

  - Previously, a deadlock in some cases occurred during an
    IdM upgrade, which could cause the IdM server to become
    unresponsive. With this update, the Schema Compatibility
    plug-in has been adjusted not to parse the subtree that
    contains the configuration of the DNA plug-in, which
    prevents this deadlock from triggering.

  - When using the extdom plug-in of IdM to handle large
    groups, user lookups and group lookups previously failed
    due to insufficient buffer size. With this update, the
    getgrgid_r() call gradually increases the buffer length
    if needed, and the described failure of extdom thus no
    longer occurs."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1503&L=scientific-linux-errata&T=0&P=4007
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?68860c92"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/27");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-admintools-4.1.0-18.sl7_1.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-client-4.1.0-18.sl7_1.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-debuginfo-4.1.0-18.sl7_1.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-python-4.1.0-18.sl7_1.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-server-4.1.0-18.sl7_1.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-server-trust-ad-4.1.0-18.sl7_1.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"slapi-nis-0.54-3.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"slapi-nis-debuginfo-0.54-3.el7_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
