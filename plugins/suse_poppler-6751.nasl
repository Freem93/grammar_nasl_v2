#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43621);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/22 20:42:28 $");

  script_cve_id("CVE-2009-3608", "CVE-2009-4035");

  script_name(english:"SuSE 10 Security Update : poppler (ZYPP Patch Number 6751)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of poppler fixes two security issues :

  - Integer overflow in the ObjectStream::ObjectStream
    function in XRef.cc in Xpdf 3.x before 3.02pl4 and
    Poppler before 0.12.1, as used in GPdf, kdegraphics
    KPDF, CUPS pdftops, and teTeX, might allow remote
    attackers to execute arbitrary code via a crafted PDF
    document that triggers a heap-based buffer overflow.
    (CVE-2009-3608)

  - A indexing error in FoFiType1::parse() was fixed that
    could be used by attackers to corrupt memory and
    potentially execute code. (CVE-2009-4035)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3608.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4035.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6751.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(94, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:2, reference:"poppler-0.4.4-19.25")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"poppler-devel-0.4.4-19.25")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"poppler-glib-0.4.4-19.25")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"poppler-qt-0.4.4-19.25")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"poppler-0.4.4-19.25")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"poppler-glib-0.4.4-19.25")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"poppler-qt-0.4.4-19.25")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
