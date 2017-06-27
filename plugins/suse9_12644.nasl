#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49759);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/04/23 18:21:33 $");

  script_cve_id("CVE-2010-3069");

  script_name(english:"SuSE9 Security Update : Samba (YOU Patch Number 12644)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow in the sid_parse() function of samba could
potentially be exploited by remote attackers to execute arbitrary
code. (CVE-2010-3069)

Additionally the update also contains fixes for the following
non-security issues :

  - bnc#567013 - Failed to join ADS Domain

  - bnc#592198 - Samba 3.0 / 3.2 doesn't work with Windows
    2008 R2 (NTLMv2)

  - bnc#599873 - Problem using NTLM authentication with
    2008R2

  - bnc#613459 - winbindd crashes in rpcclisettimeout"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3069.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 12644.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SUSE9", reference:"libsmbclient-3.0.26a-0.17")) flag++;
if (rpm_check(release:"SUSE9", reference:"libsmbclient-devel-3.0.26a-0.17")) flag++;
if (rpm_check(release:"SUSE9", reference:"samba-3.0.26a-0.17")) flag++;
if (rpm_check(release:"SUSE9", reference:"samba-client-3.0.26a-0.17")) flag++;
if (rpm_check(release:"SUSE9", reference:"samba-doc-3.0.26a-0.17")) flag++;
if (rpm_check(release:"SUSE9", reference:"samba-pdb-3.0.26a-0.17")) flag++;
if (rpm_check(release:"SUSE9", reference:"samba-python-3.0.26a-0.17")) flag++;
if (rpm_check(release:"SUSE9", reference:"samba-vscan-0.3.6b-0.45")) flag++;
if (rpm_check(release:"SUSE9", reference:"samba-winbind-3.0.26a-0.17")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"libsmbclient-32bit-9-201009141040")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"samba-32bit-9-201009141040")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"samba-client-32bit-9-201009141040")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"samba-winbind-32bit-9-201009141040")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
