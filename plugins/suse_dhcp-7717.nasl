#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56606);
  script_version ("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/05/17 11:05:45 $");

  script_cve_id("CVE-2011-2748", "CVE-2011-2749");

  script_name(english:"SuSE 10 Security Update : dhcp (ZYPP Patch Number 7717)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of dhcp fixes two Denial of Service (CVE-2011-2748 /
CVE-2011-2749) vulnerabilities caused by specially crafted BOOTP
packets.

Additionally, the alias IP address handling of dhclient-script was
fixed to not wipe out iptables connmark when renewing the lease."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2748.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2749.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7717.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES10", sp:3, reference:"dhcp-3.0.7-7.7.14.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"dhcp-client-3.0.7-7.7.14.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"dhcp-devel-3.0.7-7.7.14.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"dhcp-relay-3.0.7-7.7.14.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"dhcp-server-3.0.7-7.7.14.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
