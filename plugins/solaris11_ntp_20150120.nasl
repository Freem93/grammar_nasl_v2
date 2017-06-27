#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80934);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/11/01 04:40:11 $");

  script_cve_id("CVE-2014-9293", "CVE-2014-9294", "CVE-2014-9295", "CVE-2014-9296");

  script_name(english:"Oracle Solaris Third-Party Patch Update : ntp (multiple_vulnerabilities_in_ntp)");
  script_summary(english:"Check for the 'entire' version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch for third-party
software."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Solaris system is missing necessary patches to address
security updates :

  - Multiple stack-based buffer overflows in ntpd in NTP
    before 4.2.8 allow remote attackers to execute arbitrary
    code via a crafted packet, related to (1) the
    crypto_recv function when the Autokey Authentication
    feature is used, (2) the ctl_putdata function, and (3)
    the configure function. (CVE-2014-9295)

  - The receive function in ntp_proto.c in ntpd in NTP
    before 4.2.8 continues to execute after detecting a
    certain authentication error, which might allow remote
    attackers to trigger an unintended association change
    via crafted packets. (CVE-2014-9296)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_ntp
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a9584c5"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.2.6.4.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:ntp");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris11/release", "Host/Solaris11/pkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Solaris11/release");
if (isnull(release)) audit(AUDIT_OS_NOT, "Solaris11");
pkg_list = solaris_pkg_list_leaves();
if (isnull (pkg_list)) audit(AUDIT_PACKAGE_LIST_MISSING, "Solaris pkg-list packages");

if (empty_or_null(egrep(string:pkg_list, pattern:"^ntp$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.2.6.0.4.0", sru:"SRU 11.2.6.4.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : ntp\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "ntp");
