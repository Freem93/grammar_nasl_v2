#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65908);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/09/15 00:18:57 $");

  script_cve_id("CVE-2012-3499", "CVE-2012-4558");

  script_name(english:"SuSE 10 Security Update : Apache (ZYPP Patch Number 8530)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Apache2 has been updated to fix multiple XSS flaws.

  - Multiple cross-site scripting (XSS) vulnerabilities in
    the balancer_handler function in the manager interface
    in mod_proxy_balancer.c in the mod_proxy_balancer module
    in the Apache HTTP Server potentially allowed remote
    attackers to inject arbitrary web script or HTML via a
    crafted string. (CVE-2012-4558)

  - Multiple cross-site scripting (XSS) vulnerabilities in
    the Apache HTTP Server allowed remote attackers to
    inject arbitrary web script or HTML via vectors
    involving hostnames and URIs in the (1) mod_imagemap,
    (2) mod_info, (3) mod_ldap, (4) mod_proxy_ftp, and (5)
    mod_status modules. (CVE-2012-3499)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3499.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4558.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8530.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES10", sp:4, reference:"apache2-2.2.3-16.48.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"apache2-devel-2.2.3-16.48.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"apache2-doc-2.2.3-16.48.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"apache2-example-pages-2.2.3-16.48.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"apache2-prefork-2.2.3-16.48.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"apache2-worker-2.2.3-16.48.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
