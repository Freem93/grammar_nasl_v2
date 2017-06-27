#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41102);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2012/04/23 18:14:41 $");

  script_cve_id("CVE-2006-2191", "CVE-2006-2941", "CVE-2006-3636");

  script_name(english:"SuSE9 Security Update : mailman (YOU Patch Number 11243)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of mailman fixes the following security issues :

  - A malicious user could visit a specially crafted URI and
    inject an apparent log message into Mailman's error log
    which might induce an unsuspecting administrator to
    visit a phishing site. This has been blocked. Thanks to
    Moritz Naumann for its discovery.

  - Fixed denial of service attack which can be caused by
    some standards-breaking RFC 2231 formatted headers.
    CVE-2006-2941.

  - Several cross-site scripting issues have been fixed.
    Thanks to Moritz Naumann for their discovery.
    CVE-2006-3636

  - Fixed an unexploitable format string vulnerability.
    Discovery and fix by Karl Chen. Analysis of
    non-exploitability by Martin 'Joey' Schulze. Also thanks
    go to Lionel Elie Mamane. CVE-2006-2191."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-2191.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-2941.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-3636.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 11243.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/17");
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
if (rpm_check(release:"SUSE9", reference:"mailman-2.1.4-83.27")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
