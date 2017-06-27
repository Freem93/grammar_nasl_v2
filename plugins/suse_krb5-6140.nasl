#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41542);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/22 20:42:26 $");

  script_cve_id("CVE-2009-0844", "CVE-2009-0845", "CVE-2009-0846", "CVE-2009-0847");

  script_name(english:"SuSE 10 Security Update : Kerberos (ZYPP Patch Number 6140)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Clients sending negotiation requests with invalid flags could crash
the kerberos server. (CVE-2009-0845)

GSS-API clients could crash when reading from an invalid address
space. (CVE-2009-0844)

Invalid length checks could crash applications using the kerberos
ASN.1 parser. (CVE-2009-0847)

Under certain circumstances the ASN.1 parser could free an
uninitialized pointer which could crash a kerberos server or even lead
to execution of arbitrary code. (CVE-2009-0846)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0844.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0845.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0846.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0847.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6140.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:2, reference:"krb5-1.4.3-19.41")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"krb5-client-1.4.3-19.41")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"krb5-devel-1.4.3-19.41")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"krb5-32bit-1.4.3-19.41")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"krb5-devel-32bit-1.4.3-19.41")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"krb5-1.4.3-19.41")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"krb5-apps-clients-1.4.3-19.41")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"krb5-apps-servers-1.4.3-19.41")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"krb5-client-1.4.3-19.41")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"krb5-devel-1.4.3-19.41")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"krb5-server-1.4.3-19.41")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"krb5-32bit-1.4.3-19.41")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"krb5-devel-32bit-1.4.3-19.41")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
