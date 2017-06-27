#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99994);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/05 17:09:04 $");

  script_cve_id("CVE-2017-1081");
  script_bugtraq_id(98089);
  script_osvdb_id(156574);
  script_xref(name:"IAVA", value:"2017-A-0133");

  script_name(english:"FreeBSD < 10.3-RELEASE-p19 / 11.0 < 11.0-RELEASE-p10 ipfilter Kernel Module Packet Fragment DoS (FreeBSD-SA-17:04.ipfilter)");
  script_summary(english:"Checks for the version of the FreeBSD kernel.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The version of the FreeBSD kernel running on the remote host is prior
to 10.3-RELEASE-p19 or 11.0 prior to 11.0-RELEASE-p10. It, therefore,
affected by a use-after-free error in the ipfilter kernel module
(ipl.ko) due to freeing the wrong entry in a hash table when matching
packet fragments are processed. An unauthenticated, remote attacker
can exploit this issue, via specially crafted packet fragments, to
cause a panic and reboot, resulting in a denial of service condition.

Note that this issue only affects hosts with ipfilter enabled and the
'keep state' or 'keep frags' rule options enabled.");
  # https://www.freebsd.org/security/advisories/FreeBSD-SA-17:04.ipfilter.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e471fb57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to FreeBSD version 10.3-RELEASE-p19 / 11.0-RELEASE-p10 or
later. Alternatively, apply the patch referenced in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info", "Settings/ParanoidReport");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/FreeBSD/release");
if (!release) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);

# Patches are available and ipfilter must be enabled with
# "keep state" or "keep frags" rule options enabled
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = NULL;

if (release =~ "^FreeBSD-([0-9]|10\.[0-3])($|[^0-9])")
  fix = "FreeBSD-10.3_19";
else if (release =~ "^FreeBSD-11\.0($|[^0-9])")
  fix = "FreeBSD-11.0_10";

if (isnull(fix) || pkg_cmp(pkg:release, reference:fix) >= 0)
  audit(AUDIT_HOST_NOT, "affected");  

report =
  '\n  Installed version : ' + release +
  '\n  Fixed version     : ' + fix +
  '\n';
security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
