#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41214);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2012/04/23 18:14:42 $");

  script_cve_id("CVE-2008-1105");

  script_name(english:"SuSE9 Security Update : Samba (YOU Patch Number 12165)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Samba has been updated to fix a security problem :

  - Secunia research discovered a vulnerability in Samba,
    which can be exploited by malicious people to compromise
    a vulnerable system. (CVE-2008-1105)

The vulnerability is caused due to a boundary error within the
'receive_smb_raw()' function in lib/util_sock.c when parsing SMB
packets. This can be exploited to cause a heap-based buffer overflow
via an overly large SMB packet received in a client context."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1105.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 12165.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2012 Tenable Network Security, Inc.");
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
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 9 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SUSE9", reference:"libsmbclient-3.0.26a-0.9")) flag++;
if (rpm_check(release:"SUSE9", reference:"libsmbclient-devel-3.0.26a-0.9")) flag++;
if (rpm_check(release:"SUSE9", reference:"samba-3.0.26a-0.9")) flag++;
if (rpm_check(release:"SUSE9", reference:"samba-client-3.0.26a-0.9")) flag++;
if (rpm_check(release:"SUSE9", reference:"samba-doc-3.0.26a-0.9")) flag++;
if (rpm_check(release:"SUSE9", reference:"samba-pdb-3.0.26a-0.9")) flag++;
if (rpm_check(release:"SUSE9", reference:"samba-python-3.0.26a-0.9")) flag++;
if (rpm_check(release:"SUSE9", reference:"samba-vscan-0.3.6b-0.37")) flag++;
if (rpm_check(release:"SUSE9", reference:"samba-winbind-3.0.26a-0.9")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"libsmbclient-32bit-9-200805282142")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"samba-32bit-9-200805282142")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"samba-client-32bit-9-200805282142")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"samba-winbind-32bit-9-200805282142")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
