#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(69169);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/13 15:30:42 $");

  script_cve_id("CVE-2013-3556", "CVE-2013-3557", "CVE-2013-4074", "CVE-2013-4081", "CVE-2013-4083");

  script_name(english:"SuSE 10 Security Update : wireshark (ZYPP Patch Number 8659)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This wireshark version update to 1.6.16 includes several security and
general bug fixes.

http://www.wireshark.org/docs/relnotes/wireshark-1.6.16.html

  - The CAPWAP dissector could crash. Discovered by Laurent
    Butti. (CVE-2013-4074)

  - The HTTP dissector could overrun the stack. Discovered
    by David Keeler. (CVE-2013-4081)

  - The DCP ETSI dissector could crash. (CVE-2013-4083)
    http://www.wireshark.org/docs/relnotes/wireshark-1.6.15.
    html

  - The ASN.1 BER dissector could crash. ( CVE-2013-3556 /
    CVE-2013-3557 ) The releases also fix various
    non-security issues.

Additionally, a crash in processing SCTP filters has been fixed.
(bug#816887)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3556.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3557.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4074.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4081.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4083.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8659.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:4, reference:"wireshark-1.6.16-0.5.5")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"wireshark-1.6.16-0.5.5")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"wireshark-devel-1.6.16-0.5.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
