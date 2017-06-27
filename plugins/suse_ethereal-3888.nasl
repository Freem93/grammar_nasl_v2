#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(29421);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/01/13 15:30:42 $");

  script_cve_id("CVE-2007-3389", "CVE-2007-3390", "CVE-2007-3391", "CVE-2007-3392", "CVE-2007-3393");

  script_name(english:"SuSE 10 Security Update : ethereal (ZYPP Patch Number 3888)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Various security problems were fixed in the wireshark 0.99.6 release,
which were backported to ethereal (predecessor of wireshark) :

  - Wireshark allowed remote attackers to cause a denial of
    service (crash) via a crafted chunked encoding in an
    HTTP response, possibly related to a zero-length
    payload. (CVE-2007-3389)

  - Wireshark when running on certain systems, allowed
    remote attackers to cause a denial of service (crash)
    via crafted iSeries capture files that trigger a
    SIGTRAP. (CVE-2007-3390)

  - Wireshark allowed remote attackers to cause a denial of
    service (memory consumption) via a malformed DCP ETSI
    packet that triggers an infinite loop. (CVE-2007-3391)

  - Wireshark allowed remote attackers to cause a denial of
    service via malformed (1) SSL or (2) MMS packets that
    trigger an infinite loop. (CVE-2007-3392)

  - Off-by-one error in the DHCP/BOOTP dissector in
    Wireshark allowed remote attackers to cause a denial of
    service (crash) via crafted DHCP-over-DOCSIS packets.
    (CVE-2007-3393)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3389.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3390.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3391.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3392.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3393.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 3888.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:1, reference:"ethereal-0.10.14-16.16")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"ethereal-0.10.14-16.16")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"ethereal-devel-0.10.14-16.16")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
