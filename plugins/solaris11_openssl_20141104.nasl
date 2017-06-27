#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80725);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/10/25 16:58:36 $");

  script_cve_id("CVE-2014-3513", "CVE-2014-3566", "CVE-2014-3567", "CVE-2014-3568");

  script_name(english:"Oracle Solaris Third-Party Patch Update : openssl (multiple_vulnerabilities_in_openssl6) (POODLE)");
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

  - Memory leak in d1_srtp.c in the DTLS SRTP extension in
    OpenSSL 1.0.1 before 1.0.1j allows remote attackers to
    cause a denial of service (memory consumption) via a
    crafted handshake message. (CVE-2014-3513)

  - The SSL protocol 3.0, as used in OpenSSL through 1.0.1i
    and other products, uses nondeterministic CBC padding,
    which makes it easier for man-in-the-middle attackers to
    obtain cleartext data via a padding-oracle attack, aka
    the 'POODLE' issue. (CVE-2014-3566)

  - Memory leak in the tls_decrypt_ticket function in
    t1_lib.c in OpenSSL before 0.9.8zc, 1.0.0 before 1.0.0o,
    and 1.0.1 before 1.0.1j allows remote attackers to cause
    a denial of service (memory consumption) via a crafted
    session ticket that triggers an integrity-check failure.
    (CVE-2014-3567)

  - OpenSSL before 0.9.8zc, 1.0.0 before 1.0.0o, and 1.0.1
    before 1.0.1j does not properly enforce the no-ssl3
    build option, which allows remote attackers to bypass
    intended access restrictions via an SSL 3.0 handshake,
    related to s23_clnt.c and s23_srvr.c. (CVE-2014-3568)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_openssl6
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d5e77af"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.2.3.5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:openssl");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/04");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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

if (solaris_check_release(release:"0.5.11-0.175.2.3.0.5.0", sru:"SRU 11.2.3.5.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : openssl\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "openssl");
