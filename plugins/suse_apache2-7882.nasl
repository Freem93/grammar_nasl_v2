#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57298);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/01/13 15:30:42 $");

  script_cve_id("CVE-2011-1473", "CVE-2011-3368", "CVE-2011-3607", "CVE-2011-3639", "CVE-2011-4317");

  script_name(english:"SuSE 10 Security Update : Apache2 (ZYPP Patch Number 7882)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes several security issues in the Apache2 webserver.

  - This update also includes several fixes for a mod_proxy
    reverse exposure via RewriteRule or ProxyPassMatch
    directives. (CVE-2011-3639 / CVE-2011-3368 /
    CVE-2011-4317)

  - Fixed the SSL renegotiation DoS by disabling
    renegotiation by default. (CVE-2011-1473)

  - Integer overflow in ap_pregsub function resulting in a
    heap-based buffer overflow could potentially allow local
    attackers to gain privileges. (CVE-2011-3607)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1473.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-3368.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-3607.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-3639.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-4317.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7882.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-14-410");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES10", sp:4, reference:"apache2-2.2.3-16.42.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"apache2-devel-2.2.3-16.42.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"apache2-doc-2.2.3-16.42.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"apache2-example-pages-2.2.3-16.42.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"apache2-prefork-2.2.3-16.42.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"apache2-worker-2.2.3-16.42.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
