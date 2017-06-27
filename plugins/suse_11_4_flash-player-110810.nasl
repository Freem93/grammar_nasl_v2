#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update flash-player-4976.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75837);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:10:33 $");

  script_cve_id("CVE-2011-2130", "CVE-2011-2134", "CVE-2011-2135", "CVE-2011-2136", "CVE-2011-2137", "CVE-2011-2138", "CVE-2011-2139", "CVE-2011-2140", "CVE-2011-2414", "CVE-2011-2415", "CVE-2011-2416", "CVE-2011-2417", "CVE-2011-2425");

  script_name(english:"openSUSE Security Update : flash-player (openSUSE-SU-2011:0897-1)");
  script_summary(english:"Check for the flash-player-4976 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
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

  - CVE-2011-2425: CVSS v2 Base Score: 6.8
    (AV:N/AC:M/Au:N/C:P/I:P/A:P)

This update resolves a buffer overflow vulnerability that could lead
to code execution (CVE-2011-2130).

This update resolves a buffer overflow vulnerability that could lead
to code execution (CVE-2011-2134).

This update resolves a memory corruption vulnerability that could lead
to code execution (CVE-2011-2135).

This update resolves an integer overflow vulnerability that could lead
to code execution (CVE-2011-2136).

This update resolves a buffer overflow vulnerability that could lead
to code execution (CVE-2011-2137).

This update resolves an integer overflow vulnerability that could lead
to code execution (CVE-2011-2138).

This update resolves a cross-site information disclosure vulnerability
that could lead to code execution (CVE-2011-2139).

This update resolves a memory corruption vulnerability that could lead
to code execution (CVE-2011-2140).

This update resolves a buffer overflow vulnerability that could lead
to code execution (CVE-2011-2414).

This update resolves a buffer overflow vulnerability that could lead
to code execution (CVE-2011-2415).

This update resolves an integer overflow vulnerability that could lead
to code execution (CVE-2011-2416).

This update resolves a memory corruption vulnerability that could lead
to code execution (CVE-2011-2417).

This update resolves a memory corruption vulnerability that could lead
to code execution (CVE-2011-2425)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-08/msg00018.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=711427"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected flash-player package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player MP4 SequenceParameterSetNALUnit Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686)$") audit(AUDIT_ARCH_NOT, "i586 / i686", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"flash-player-10.3.183.5-0.2.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "flash-player");
}
