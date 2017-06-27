#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58225);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/04/23 18:53:58 $");

  script_cve_id("CVE-2005-1625");

  script_name(english:"SuSE9 Security Update : Acrobat Reader (YOU Patch Number 10316)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a buffer overflow in Acrobat Reader versions 5 and
7, where an attacker could execute code by providing a handmade PDF to
the viewer.

The Acrobat Reader 5 versions of 9.1 and 9.2 were upgraded to Acrobat
Reader 7. This version upgrade can cause new dependencies to appear,
please check with the YaST Software Package Installation frontend if
there are new dependencies and install the required packages.

Since this attack could be done via E-Mail messages or webpages, this
should be considered to be remote exploitable.

This issue is tracked by the Mitre CVE ID CVE-2005-1625."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2005-1625.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 10316.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"acroread-7.0.0-5.4")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"atk-1.4.1-128.2")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"atk-32bit-9-200507121454")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"atk-doc-1.4.1-128.2")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"curl-32bit-9-200507121454")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"glib2-2.2.3-117.2")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"glib2-32bit-9-200507121454")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"glibc-locale-32bit-9-200507121454")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"gtk2-2.2.4-125.5")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"gtk2-32bit-9-200507121454")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"pango-1.2.5-174.4")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"pango-32bit-9-200507121454")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
