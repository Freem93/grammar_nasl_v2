#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29540);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2014/05/30 20:03:12 $");

  script_cve_id("CVE-2007-4752");

  script_name(english:"SuSE 10 Security Update : OpenSSH (ZYPP Patch Number 4580)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a bug in ssh's cookie handling code. It does not
properly handle the situation when an untrusted cookie cannot be
created and uses a trusted X11 cookie instead. This allows attackers
to violate the intended policy and gain privileges by causing an X
client to be treated as trusted. (CVE-2007-4752) Additionally this
update fixes a bug introduced with the last security update for
openssh. When the SSH daemon wrote to stderr (for instance, to warn
about the presence of a deprecated option like
PAMAuthenticationViaKbdInt in its configuration file), SIGALRM was
blocked for SSH sessions. This resulted in problems with processes
which rely on SIGALRM, such as ntpdate."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-4752.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 4580.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:1, reference:"openssh-4.2p1-18.30")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"openssh-askpass-4.2p1-18.30")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"openssh-4.2p1-18.30")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"openssh-askpass-4.2p1-18.30")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
