#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29357);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/05/22 11:17:46 $");

  script_cve_id("CVE-2006-5462", "CVE-2006-5463", "CVE-2006-5464", "CVE-2006-5747", "CVE-2006-5748");

  script_name(english:"SuSE 10 Security Update : Mozilla Firefox (ZYPP Patch Number 2258)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings MozillaFirefox to the security update release
1.5.0.8, including the following security fixes.

Full details can be found on:
http://www.mozilla.org/projects/security/known-vulnerabiliti es.html

  - Is split into 3 sub-entries, for ongoing stability
    improvements in the Mozilla browsers: CVE-2006-5464:
    Layout engine flaws were fixed. CVE-2006-5747: A
    xml.prototype.hasOwnProperty flaw was fixed.
    CVE-2006-5748: Fixes were applied to the JavaScript
    engine. (MFSA 2006-65)

  - reported that RSA digital signatures with a low exponent
    (typically 3) could be forged. Firefox and Thunderbird
    1.5.0.7, which incorporated NSS version 3.10.2, were
    incompletely patched and remained vulnerable to a
    variant of this attack. (MFSA 2006-66 / CVE-2006-5462:
    MFSA 2006-60)

  - shutdown demonstrated that it was possible to modify a
    Script object while it was executing, potentially
    leading to the execution of arbitrary JavaScript
    bytecode. (MFSA 2006-67 / CVE-2006-5463)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2006/mfsa2006-60.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-5462.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-5463.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-5464.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-5747.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-5748.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 2258.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/12");
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
if (rpm_check(release:"SLED10", sp:0, cpu:"i586", reference:"MozillaFirefox-1.5.0.8-0.2")) flag++;
if (rpm_check(release:"SLED10", sp:0, cpu:"i586", reference:"MozillaFirefox-translations-1.5.0.8-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"i586", reference:"MozillaFirefox-1.5.0.8-0.2")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"i586", reference:"MozillaFirefox-translations-1.5.0.8-0.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
