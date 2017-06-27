#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(62097);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/10/21 02:33:23 $");

  script_cve_id("CVE-2012-4048", "CVE-2012-4049", "CVE-2012-4285", "CVE-2012-4288", "CVE-2012-4289", "CVE-2012-4290", "CVE-2012-4291", "CVE-2012-4292", "CVE-2012-4293", "CVE-2012-4296");

  script_name(english:"SuSE 10 Security Update : wireshark (ZYPP Patch Number 8267)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"wireshark was updated to 1.4.15 to fix multiple security issues.

Issues fixed :

  - fix bnc#776038(CVE-2012-4285 / CVE-2012-4288 /
    CVE-2012-4289 / CVE-2012-4296 / CVE-2012-4291 /
    CVE-2012-4292 / CVE-2012-4293 / CVE-2012-4290),
    bnc#772738 (CVE-2012-4048 / CVE-2012-4049)(fixed
    upstream)

  - Security fixes: o wnpa-sec-2012-13 The DCP ETSI
    dissector could trigger a zero division. Reported by
    Laurent Butti. (Bug 7566) o wnpa-sec-2012-15 The XTP
    dissector could go into an infinite loop. Reported by
    Ben Schmidt. (Bug 7571) o wnpa-sec-2012-17 The AFP
    dissector could go into a large loop. Reported by Stefan
    Cornelius. (Bug 7603) o wnpa-sec-2012-18 The RTPS2
    dissector could overflow a buffer. Reported by Laurent
    Butti. (Bug 7568) o wnpa-sec-2012-20 The CIP dissector
    could exhaust system memory. Reported y Ben Schmidt.
    (Bug 7570) o wnpa-sec-2012-21 The STUN dissector could
    crash. Reported by Laurent Butti. (Bug 7569) o
    wnpa-sec-2012-22 The EtherCAT Mailbox dissector could
    abort. Reported by Laurent Butti. (Bug 7562) o
    wnpa-sec-2012-23 The CTDB dissector could go into a
    large loop. Reported by Ben Schmidt. (Bug 7573)

  - Bug fixes: o Wireshark crashes on opening very short NFS
    pcap file. (Bug 7498)

  - Updated Protocol Support o AFP, Bluetooth L2CAP, CIP,
    CTDB, DCP ETSI, EtherCAT Mailbox, FC Link Control LISP,
    NFS, RTPS2, SCTP, STUN, XTP"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4048.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4049.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4285.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4288.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4289.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4290.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4291.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4292.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4293.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4296.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8267.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/14");
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
if (rpm_check(release:"SLED10", sp:4, reference:"wireshark-1.4.15-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"wireshark-1.4.15-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"wireshark-devel-1.4.15-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else exit(0, "The host is not affected.");
