#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41119);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2012/04/23 18:14:41 $");

  script_cve_id("CVE-2006-5876");

  script_name(english:"SuSE9 Security Update : Red Carpet (YOU Patch Number 11461)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a bug in the HTTP header parsing code of the
included libsoup. This bug makes rcd vulnerable to a remote
denial-of-service attack. (CVE-2006-5876)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-5876.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 11461.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/21");
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
if (rpm_check(release:"SUSE9", reference:"libredcarpet-2.4.9-1.9")) flag++;
if (rpm_check(release:"SUSE9", reference:"libredcarpet-python-2.4.9-1.9")) flag++;
if (rpm_check(release:"SUSE9", reference:"libredcarpet-tools-2.4.9-1.9")) flag++;
if (rpm_check(release:"SUSE9", reference:"python-openssl-0.6-3.5")) flag++;
if (rpm_check(release:"SUSE9", reference:"rcd-2.4.9-1.18")) flag++;
if (rpm_check(release:"SUSE9", reference:"rcd-devel-2.4.9-1.18")) flag++;
if (rpm_check(release:"SUSE9", reference:"rcd-modules-2.4.9-1.6")) flag++;
if (rpm_check(release:"SUSE9", reference:"rcd-modules-devel-2.4.9-1.6")) flag++;
if (rpm_check(release:"SUSE9", reference:"red-carpet-2.4.9-1.15")) flag++;
if (rpm_check(release:"SUSE9", reference:"rug-2.4.9-1.14")) flag++;
if (rpm_check(release:"SUSE9", reference:"xmlrpc-c-0.9.10-21.3")) flag++;
if (rpm_check(release:"SUSE9", reference:"xmlrpc-c-devel-0.9.10-21.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
