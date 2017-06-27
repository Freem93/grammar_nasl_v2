#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49834);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/22 20:32:45 $");

  script_cve_id("CVE-2010-0547", "CVE-2010-0926");

  script_name(english:"SuSE 10 Security Update : Samba (ZYPP Patch Number 6921)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"With enabled 'wide links' samba follows symbolic links on the server
side, therefore allowing clients to overwrite arbitrary files
(CVE-2010-0926). This update changes the default setting to have 'wide
links' disabled by default. The new default only works if 'wide links'
is not set explicitly in smb.conf.

Due to a race condition in mount.cifs a local attacker could corrupt
/etc/mtab if mount.cifs is installed setuid root. mount.cifs is not
setuid root by default and it's not recommended to change that.
(CVE-2010-0547)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0547.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0926.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6921.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_cwe_id(20, 22);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:3, reference:"cifs-mount-3.0.36-0.9.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"ldapsmb-1.34b-25.9.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libsmbclient-3.0.36-0.9.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"libsmbclient-devel-3.0.36-0.9.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"samba-3.0.36-0.9.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"samba-client-3.0.36-0.9.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"samba-krb-printing-3.0.36-0.9.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"samba-vscan-0.3.6b-43.9.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"samba-winbind-3.0.36-0.9.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"libsmbclient-32bit-3.0.36-0.9.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"samba-32bit-3.0.36-0.9.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"samba-client-32bit-3.0.36-0.9.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"samba-winbind-32bit-3.0.36-0.9.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"cifs-mount-3.0.36-0.9.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"ldapsmb-1.34b-25.9.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"libmsrpc-3.0.36-0.9.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"libmsrpc-devel-3.0.36-0.9.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"libsmbclient-3.0.36-0.9.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"libsmbclient-devel-3.0.36-0.9.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"samba-3.0.36-0.9.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"samba-client-3.0.36-0.9.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"samba-krb-printing-3.0.36-0.9.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"samba-python-3.0.36-0.9.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"samba-vscan-0.3.6b-43.9.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"samba-winbind-3.0.36-0.9.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"libsmbclient-32bit-3.0.36-0.9.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"samba-32bit-3.0.36-0.9.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"samba-client-32bit-3.0.36-0.9.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"samba-winbind-32bit-3.0.36-0.9.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else exit(0, "The host is not affected.");
