#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34441);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2012/06/14 20:21:38 $");

  script_cve_id("CVE-2008-2952");

  script_name(english:"SuSE 10 Security Update : OpenLDAP 2 (ZYPP Patch Number 5511)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a security problem in the liblber client library of
openldap that allowed remote attackers to cause a denial of service
(program termination) via crafted ASN.1 BER datagrams, which triggers
an assertion error. (CVE-2008-2952) Additionally a bug was fixed in
ldap_free_connection which could result in client crashes when the
server closed a connection while an operation is active."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-2952.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 5511.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2012 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:1, reference:"openldap2-2.3.32-0.25.12")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"openldap2-client-2.3.32-0.23.12")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"openldap2-devel-2.3.32-0.23.12")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"openldap2-client-32bit-2.3.32-0.23.12")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"openldap2-devel-32bit-2.3.32-0.23.12")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"openldap2-2.3.32-0.30")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"openldap2-client-2.3.32-0.28")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"openldap2-devel-2.3.32-0.28")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"openldap2-client-32bit-2.3.32-0.28")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"openldap2-devel-32bit-2.3.32-0.28")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"openldap2-2.3.32-0.25.12")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"openldap2-back-meta-2.3.32-0.25.12")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"openldap2-back-perl-2.3.32-0.25.12")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"openldap2-client-2.3.32-0.23.12")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"openldap2-devel-2.3.32-0.23.12")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"openldap2-client-32bit-2.3.32-0.23.12")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"openldap2-devel-32bit-2.3.32-0.23.12")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"openldap2-2.3.32-0.30")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"openldap2-back-meta-2.3.32-0.30")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"openldap2-back-perl-2.3.32-0.30")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"openldap2-client-2.3.32-0.28")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"openldap2-devel-2.3.32-0.28")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"openldap2-client-32bit-2.3.32-0.28")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"openldap2-devel-32bit-2.3.32-0.28")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
