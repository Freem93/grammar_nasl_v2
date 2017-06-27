#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80724);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/28 19:00:57 $");

  script_cve_id("CVE-2014-3508", "CVE-2014-3511");

  script_name(english:"Oracle Solaris Third-Party Patch Update : openssl (cve_2014_3508_information_disclosure)");
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

  - The OBJ_obj2txt function in crypto/objects/obj_dat.c in
    OpenSSL 0.9.8 before 0.9.8zb, 1.0.0 before 1.0.0n, and
    1.0.1 before 1.0.1i, when pretty printing is used, does
    not ensure the presence of '\0' characters, which allows
    context-dependent attackers to obtain sensitive
    information from process stack memory by reading output
    from X509_name_oneline, X509_name_print_ex, and
    unspecified other functions. (CVE-2014-3508)

  - The ssl23_get_client_hello function in s23_srvr.c in
    OpenSSL 1.0.1 before 1.0.1i allows man-in-the-middle
    attackers to force the use of TLS 1.0 by triggering
    ClientHello message fragmentation in communication
    between a client and server that both support later TLS
    versions, related to a 'protocol downgrade' issue.
    (CVE-2014-3511)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2014_3508_information_disclosure
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?54ae33d6"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2014_3511_cryptographic_vulnerability
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75b291e6"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.2.2.5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:openssl");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^openssl$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.2.2.0.5.0", sru:"SRU 11.2.2.5.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : openssl\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "openssl");
