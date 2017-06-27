#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(31991);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/22 20:42:28 $");

  script_cve_id("CVE-2007-4879", "CVE-2008-1195", "CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235", "CVE-2008-1236", "CVE-2008-1237", "CVE-2008-1238", "CVE-2008-1240", "CVE-2008-1241");

  script_name(english:"SuSE 10 Security Update : epiphany (ZYPP Patch Number 5164)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes security issues also fixes in the Mozilla Firefox
2.0.0.13 update round.

Following security problems were fixed :

  - XUL popup spoofing variant (cross-tab popups). (MFSA
    2008-19 / CVE-2008-1241)

  - Java socket connection to any local port via
    LiveConnect. (MFSA 2008-18 / CVE-2008-1195 /
    CVE-2008-1240)

  - Privacy issue with SSL Client Authentication. (MFSA
    2008-17 / CVE-2007-4879)

  - HTTP Referrer spoofing with malformed URLs. (MFSA
    2008-16 / CVE-2008-1238)

  - Crashes with evidence of memory corruption
    (rv:1.8.1.13). (MFSA 2008-15 / CVE-2008-1236 /
    CVE-2008-1237)

  - JavaScript privilege escalation and arbitrary code
    execution. (MFSA 2008-14 / CVE-2008-1233 / CVE-2008-1234
    / CVE-2008-1235)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-14.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-15.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-16.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-17.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-18.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2008/mfsa2008-19.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-4879.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1195.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1233.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1234.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1235.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1236.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1237.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1238.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1240.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1241.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 5164.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(59, 79, 94, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:1, reference:"epiphany-1.8.5-14.6")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"epiphany-devel-1.8.5-14.6")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"epiphany-doc-1.8.5-14.6")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"gecko-sdk-1.8.0.14eol-0.5")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"mozilla-xulrunner-1.8.0.14eol-0.5")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner-32bit-1.8.0.14eol-0.5")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"mozilla-xulrunner-1.8.0.14eol-0.5")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner-32bit-1.8.0.14eol-0.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
