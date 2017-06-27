#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80582);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2011-3607", "CVE-2011-4317", "CVE-2012-0031", "CVE-2012-0053");

  script_name(english:"Oracle Solaris Third-Party Patch Update : apache (cve_2011_3607_buffer_overflow)");
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

  - Integer overflow in the ap_pregsub function in
    server/util.c in the Apache HTTP Server 2.0.x through
    2.0.64 and 2.2.x through 2.2.21, when the mod_setenvif
    module is enabled, allows local users to gain privileges
    via a .htaccess file with a crafted SetEnvIf directive,
    in conjunction with a crafted HTTP request header,
    leading to a heap-based buffer overflow. (CVE-2011-3607)

  - The mod_proxy module in the Apache HTTP Server 2.0.x
    through 2.0.64, and 2.2.x through 2.2.21, when the
    Revision 1179239 patch is in place, does not properly
    interact with use of (1) RewriteRule and (2)
    ProxyPassMatch pattern matches for configuration of a
    reverse proxy, which allows remote attackers to send
    requests to intranet servers via a malformed URI
    containing an @ (at sign) character and a : (colon)
    character in invalid positions. NOTE: this vulnerability
    exists because of an incomplete fix for CVE-2011-3368.
    (CVE-2011-4317)

  - scoreboard.c in the Apache HTTP Server 2.2.21 and
    earlier might allow local users to cause a denial of
    service (daemon crash during shutdown) or possibly have
    unspecified other impact by modifying a certain type
    field within a scoreboard shared memory segment, leading
    to an invalid call to the free function. (CVE-2012-0031)

  - protocol.c in the Apache HTTP Server 2.2.x through
    2.2.21 does not properly restrict header information
    during construction of Bad Request (aka 400) error
    documents, which allows remote attackers to obtain the
    values of HTTPOnly cookies via vectors involving a (1)
    long or (2) malformed header in conjunction with crafted
    web script. (CVE-2012-0053)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2011_3607_buffer_overflow
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4ab21207"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2011_4317_improper_input
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c725688c"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2012_0031_resource_management
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d9515f8"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2012_0053_information_disclosure
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c7319917"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11/11 SRU 6.6.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:apache");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^apache-2"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.0.6.0.6.0", sru:"SRU 6.6") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : apache\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "apache");
