#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57194);
  script_version ("$Revision: 1.5 $");
  script_cvs_date("$Date: 2012/06/14 20:24:38 $");

  script_cve_id("CVE-2011-2426", "CVE-2011-2427", "CVE-2011-2429", "CVE-2011-2430", "CVE-2011-2444");

  script_name(english:"SuSE 10 Security Update : flash-player (ZYPP Patch Number 7763)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update resolves

  - a universal cross-site scripting issue that could be
    used to take actions on a user's behalf on any website
    or webmail provider if the user visits a malicious
    website. (CVE-2011-2444)

    Note: There are reports that this issue is being
    exploited in the wild in active targeted attacks
    designed to trick the user into clicking on a malicious
    link delivered in an email message.

  - an AVM stack overflow issue that may allow for remote
    code execution. (CVE-2011-2426)

  - an AVM stack overflow issue that may lead to denial of
    service and code execution. (CVE-2011-2427).

  - a logic error issue which causes a browser crash and may
    lead to code execution. (CVE-2011- 2428).

  - a Flash Player security control bypass which could allow
    information disclosure. (CVE-2011-2429).

  - a streaming media logic error vulnerability which could
    lead to code execution. (CVE-2011-2430)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2426.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2427.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2429.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2430.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2444.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7763.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:4, reference:"flash-player-10.3.183.10-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
