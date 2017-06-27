#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58299);
  script_version ("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/05/17 10:53:20 $");

  script_cve_id("CVE-2012-0870");

  script_name(english:"SuSE 10 Security Update : Samba (ZYPP Patch Number 7985)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of Samba fixes a heap-based buffer overflow that could be
exploited by remote, unauthenticated attackers to crash the smbd
daemon or potentially execute arbitrary code via specially crafted SMB
AndX request packets. (CVE-2012-0870)

Also fixed two non security bugs :

  - Fix to handle domain join using NetBIOS name;.
    (bnc#633729)

  - Fixed the DFS referral response for msdfs root;.
    (bnc#703655)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0870.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7985.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:4, reference:"cifs-mount-3.0.36-0.13.18.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"ldapsmb-1.34b-25.13.18.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libsmbclient-3.0.36-0.13.18.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libsmbclient-devel-3.0.36-0.13.18.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"samba-3.0.36-0.13.18.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"samba-client-3.0.36-0.13.18.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"samba-krb-printing-3.0.36-0.13.18.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"samba-vscan-0.3.6b-43.13.18.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"samba-winbind-3.0.36-0.13.18.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"libsmbclient-32bit-3.0.36-0.13.18.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"samba-32bit-3.0.36-0.13.18.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"samba-client-32bit-3.0.36-0.13.18.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"samba-winbind-32bit-3.0.36-0.13.18.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"cifs-mount-3.0.36-0.13.18.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"ldapsmb-1.34b-25.13.18.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"libmsrpc-3.0.36-0.13.18.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"libmsrpc-devel-3.0.36-0.13.18.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"libsmbclient-3.0.36-0.13.18.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"libsmbclient-devel-3.0.36-0.13.18.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"samba-3.0.36-0.13.18.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"samba-client-3.0.36-0.13.18.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"samba-krb-printing-3.0.36-0.13.18.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"samba-python-3.0.36-0.13.18.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"samba-vscan-0.3.6b-43.13.18.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"samba-winbind-3.0.36-0.13.18.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"libsmbclient-32bit-3.0.36-0.13.18.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"samba-32bit-3.0.36-0.13.18.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"samba-client-32bit-3.0.36-0.13.18.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"samba-winbind-32bit-3.0.36-0.13.18.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
