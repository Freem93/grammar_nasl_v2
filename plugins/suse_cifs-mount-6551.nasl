#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49833);
  script_version ("$Revision: 1.7 $");
  script_cvs_date("$Date: 2013/02/10 03:36:17 $");

  script_cve_id("CVE-2009-2813", "CVE-2009-2906", "CVE-2009-2948");

  script_name(english:"SuSE 10 Security Update : Samba (ZYPP Patch Number 6551)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"samba's make_connection_snum() handles certain input incorrectly,
which may lead to disclosure of the root directory. CVE-2009-2813 has
been assigned to this issue. Additionally an information disclosure
vulnerability in mount.cifs has been fixed (CVE-2009-2948) as well as
a DoS condition. (CVE-2009-2906)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2813.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2906.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2948.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6551.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:3, reference:"cifs-mount-3.0.36-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"ldapsmb-1.34b-25.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libsmbclient-3.0.36-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libsmbclient-devel-3.0.36-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"samba-3.0.36-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"samba-client-3.0.36-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"samba-krb-printing-3.0.36-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"samba-vscan-0.3.6b-43.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"samba-winbind-3.0.36-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"libsmbclient-32bit-3.0.36-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"samba-32bit-3.0.36-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"samba-client-32bit-3.0.36-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"samba-winbind-32bit-3.0.36-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"cifs-mount-3.0.36-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"ldapsmb-1.34b-25.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"libmsrpc-3.0.36-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"libmsrpc-devel-3.0.36-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"libsmbclient-3.0.36-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"libsmbclient-devel-3.0.36-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"samba-3.0.36-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"samba-client-3.0.36-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"samba-krb-printing-3.0.36-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"samba-python-3.0.36-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"samba-vscan-0.3.6b-43.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"samba-winbind-3.0.36-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"libsmbclient-32bit-3.0.36-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"samba-32bit-3.0.36-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"samba-client-32bit-3.0.36-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"samba-winbind-32bit-3.0.36-0.7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
