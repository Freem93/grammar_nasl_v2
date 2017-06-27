#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(57193);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/11/18 01:35:31 $");

  script_cve_id("CVE-2011-2130", "CVE-2011-2134", "CVE-2011-2135", "CVE-2011-2136", "CVE-2011-2137", "CVE-2011-2138", "CVE-2011-2139", "CVE-2011-2140", "CVE-2011-2414", "CVE-2011-2415", "CVE-2011-2416", "CVE-2011-2417", "CVE-2011-2425");

  script_name(english:"SuSE 10 Security Update : flash-player (ZYPP Patch Number 7679)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The update to Flash-Player 10.3.188.5 fixes various security issues :

  - CVE-2011-2130: CVSS v2 Base Score: 6.8
    (AV:N/AC:M/Au:N/C:P/I:P/A:P)

  - CVE-2011-2134: CVSS v2 Base Score: 6.8
    (AV:N/AC:M/Au:N/C:P/I:P/A:P)

  - CVE-2011-2135: CVSS v2 Base Score: 6.8
    (AV:N/AC:M/Au:N/C:P/I:P/A:P)

  - CVE-2011-2136: CVSS v2 Base Score: 6.8
    (AV:N/AC:M/Au:N/C:P/I:P/A:P)

  - CVE-2011-2137: CVSS v2 Base Score: 6.8
    (AV:N/AC:M/Au:N/C:P/I:P/A:P)

  - CVE-2011-2138: CVSS v2 Base Score: 6.8
    (AV:N/AC:M/Au:N/C:P/I:P/A:P)

  - CVE-2011-2139: CVSS v2 Base Score: 6.8
    (AV:N/AC:M/Au:N/C:P/I:P/A:P)

  - CVE-2011-2140: CVSS v2 Base Score: 6.8
    (AV:N/AC:M/Au:N/C:P/I:P/A:P)

  - CVE-2011-2414: CVSS v2 Base Score: 6.8
    (AV:N/AC:M/Au:N/C:P/I:P/A:P)

  - CVE-2011-2415: CVSS v2 Base Score: 6.8
    (AV:N/AC:M/Au:N/C:P/I:P/A:P)

  - CVE-2011-2416: CVSS v2 Base Score: 6.8
    (AV:N/AC:M/Au:N/C:P/I:P/A:P)

  - CVE-2011-2417: CVSS v2 Base Score: 6.8
    (AV:N/AC:M/Au:N/C:P/I:P/A:P)

  - (AV:N/AC:M/Au:N/C:P/I:P/A:P) This update resolves a
    buffer overflow vulnerability that could lead to code
    execution. (CVE-2011-2130). (CVE-2011-2425: CVSS v2 Base
    Score: 6.8)

This update resolves a buffer overflow vulnerability that could lead
to code execution. (CVE-2011-2134)

This update resolves a memory corruption vulnerability that could lead
to code execution. (CVE-2011-2135)

This update resolves an integer overflow vulnerability that could lead
to code execution. (CVE-2011-2136)

This update resolves a buffer overflow vulnerability that could lead
to code execution. (CVE-2011-2137)

This update resolves an integer overflow vulnerability that could lead
to code execution. (CVE-2011-2138)

This update resolves a cross-site information disclosure vulnerability
that could lead to code execution. (CVE-2011-2139)

This update resolves a memory corruption vulnerability that could lead
to code execution. (CVE-2011-2140)

This update resolves a buffer overflow vulnerability that could lead
to code execution. (CVE-2011-2414)

This update resolves a buffer overflow vulnerability that could lead
to code execution. (CVE-2011-2415)

This update resolves an integer overflow vulnerability that could lead
to code execution. (CVE-2011-2416)

This update resolves a memory corruption vulnerability that could lead
to code execution. (CVE-2011-2417)

This update resolves a memory corruption vulnerability that could lead
to code execution. (CVE-2011-2425)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2130.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2134.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2135.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2136.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2137.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2138.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2139.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2140.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2414.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2415.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2416.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2417.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2425.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7679.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player MP4 SequenceParameterSetNALUnit Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:4, reference:"flash-player-10.3.183.5-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
