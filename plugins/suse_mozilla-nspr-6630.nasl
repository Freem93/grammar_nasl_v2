#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42421);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/05/22 11:17:46 $");

  script_cve_id("CVE-2009-0689");

  script_name(english:"SuSE 10 Security Update : mozilla-nspr (ZYPP Patch Number 6630)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a bug in the Mozilla NSPR helper libraries, which
could be used by remote attackers to potentially execute code via
JavaScript vectors.

  - Security researcher Alin Rad Pop of Secunia Research
    reported a heap-based buffer overflow in Mozilla's
    string to floating point number conversion routines.
    Using this vulnerability an attacker could craft some
    malicious JavaScript code containing a very long string
    to be converted to a floating point number which would
    result in improper memory allocation and the execution
    of an arbitrary memory location. This vulnerability
    could thus be leveraged by the attacker to run arbitrary
    code on a victim's computer. (MFSA 2009-59 /
    CVE-2009-1563)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-59.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1563.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6630.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:2, reference:"mozilla-nspr-4.8.2-1.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"mozilla-nspr-devel-4.8.2-1.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.8.2-1.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"mozilla-nspr-4.8.2-1.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"mozilla-nspr-devel-4.8.2-1.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.8.2-1.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
