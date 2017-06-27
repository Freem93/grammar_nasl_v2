#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41483);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/22 20:32:45 $");

  script_cve_id("CVE-2009-1886", "CVE-2009-1888");

  script_name(english:"SuSE 10 Security Update : Samba (ZYPP Patch Number 6343)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fixed a format string vulnerability in smbclient (CVE-2009-1886) and a
ACL bypass vulnerability in samba. (CVE-2009-1888)

Also a printing issue in KRB5 setups was fixed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1886.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1888.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6343.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(134, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/08");
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
if (rpm_check(release:"SLED10", sp:2, reference:"cifs-mount-3.0.32-0.14")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"libsmbclient-3.0.32-0.14")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"libsmbclient-devel-3.0.32-0.14")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"samba-3.0.32-0.14")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"samba-client-3.0.32-0.14")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"samba-krb-printing-3.0.32-0.14")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"samba-vscan-0.3.6b-42.85.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"samba-winbind-3.0.32-0.14")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"libsmbclient-32bit-3.0.32-0.14")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"samba-32bit-3.0.32-0.14")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"samba-client-32bit-3.0.32-0.14")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"samba-winbind-32bit-3.0.32-0.14")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"cifs-mount-3.0.32-0.14")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"libmsrpc-3.0.32-0.14")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"libmsrpc-devel-3.0.32-0.14")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"libsmbclient-3.0.32-0.14")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"libsmbclient-devel-3.0.32-0.14")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"samba-3.0.32-0.14")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"samba-client-3.0.32-0.14")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"samba-krb-printing-3.0.32-0.14")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"samba-python-3.0.32-0.14")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"samba-vscan-0.3.6b-42.85.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"samba-winbind-3.0.32-0.14")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"libsmbclient-32bit-3.0.32-0.14")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"samba-32bit-3.0.32-0.14")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"samba-client-32bit-3.0.32-0.14")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"samba-winbind-32bit-3.0.32-0.14")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
