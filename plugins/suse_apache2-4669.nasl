#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29373);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/07/20 01:58:54 $");

  script_cve_id("CVE-2006-5752", "CVE-2007-1863", "CVE-2007-3304", "CVE-2007-3847", "CVE-2007-4465");

  script_name(english:"SuSE 10 Security Update : apache2 (ZYPP Patch Number 4669)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several bugs were fixed in the Apache2 webserver :

These include the following security issues :

  - mod_status: Fix a possible XSS attack against a site
    with a public server-status page and ExtendedStatus
    enabled, for browsers which perform charset 'detection'.
    (CVE-2006-5752)

  - mod_cache: Prevent a segmentation fault if attributes
    are listed in a Cache-Control header without any value.
    (CVE-2007-1863)

  - prefork, worker, event MPMs: Ensure that the parent
    process cannot be forced to kill processes outside its
    process group. (CVE-2007-3304)

  - mod_proxy: Prevent reading past the end of a buffer when
    parsing date-related headers. PR 41144. (CVE-2007-3847)

  - mod_autoindex: Add in ContentType and Charset options to
    IndexOptions directive. This allows the admin to
    explicitly set the content-type and charset of the
    generated page. (CVE-2007-4465)

and the following non-security issues :

  - get_module_list: replace loadmodule.conf atomically

  - Use File::Temp to create good tmpdir in logresolve.pl2
    (httpd-2.x.x-logresolve.patchs)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-5752.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-1863.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3304.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3847.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-4465.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 4669.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES10", sp:1, reference:"apache2-2.2.3-16.15")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"apache2-devel-2.2.3-16.15")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"apache2-doc-2.2.3-16.15")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"apache2-example-pages-2.2.3-16.15")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"apache2-prefork-2.2.3-16.15")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"apache2-worker-2.2.3-16.15")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
