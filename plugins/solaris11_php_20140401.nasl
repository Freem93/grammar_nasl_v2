#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80736);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2011-4718", "CVE-2012-2688", "CVE-2012-3365", "CVE-2013-1635", "CVE-2013-1643", "CVE-2013-2110", "CVE-2013-4113", "CVE-2013-4248", "CVE-2013-4635", "CVE-2013-4636");

  script_name(english:"Oracle Solaris Third-Party Patch Update : php (cve_2013_4113_buffer_errors)");
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

  - Session fixation vulnerability in the Sessions subsystem
    in PHP before 5.5.2 allows remote attackers to hijack
    web sessions by specifying a session ID. (CVE-2011-4718)

  - Unspecified vulnerability in the _php_stream_scandir
    function in the stream implementation in PHP before
    5.3.15 and 5.4.x before 5.4.5 has unknown impact and
    remote attack vectors, related to an 'overflow.'
    (CVE-2012-2688)

  - The SQLite functionality in PHP before 5.3.15 allows
    remote attackers to bypass the open_basedir protection
    mechanism via unspecified vectors. (CVE-2012-3365)

  - ext/soap/soap.c in PHP before 5.3.22 and 5.4.x before
    5.4.13 does not validate the relationship between the
    soap.wsdl_cache_dir directive and the open_basedir
    directive, which allows remote attackers to bypass
    intended access restrictions by triggering the creation
    of cached SOAP WSDL files in an arbitrary directory.
    (CVE-2013-1635)

  - The SOAP parser in PHP before 5.3.23 and 5.4.x before
    5.4.13 allows remote attackers to read arbitrary files
    via a SOAP WSDL file containing an XML external entity
    declaration in conjunction with an entity reference,
    related to an XML External Entity (XXE) issue in the
    soap_xmlParseFile and soap_xmlParseMemory functions.
    NOTE: this vulnerability exists because of an incorrect
    fix for CVE-2013-1824. (CVE-2013-1643)

  - Heap-based buffer overflow in the php_quot_print_encode
    function in ext/ standard/quot_print.c in PHP before
    5.3.26 and 5.4.x before 5.4.16 allows remote attackers
    to cause a denial of service (application crash) or
    possibly have unspecified other impact via a crafted
    argument to the quoted_printable_encode function.
    (CVE-2013-2110)

  - ext/xml/xml.c in PHP before 5.3.27 does not properly
    consider parsing depth, which allows remote attackers to
    cause a denial of service (heap memory corruption) or
    possibly have unspecified other impact via a crafted
    document that is processed by the xml_parse_into_struct
    function. (CVE-2013-4113)

  - The openssl_x509_parse function in openssl.c in the
    OpenSSL module in PHP before 5.4.18 and 5.5.x before
    5.5.2 does not properly handle a '\0' character in a
    domain name in the Subject Alternative Name field of an
    X.509 certificate, which allows man-in-the-middle
    attackers to spoof arbitrary SSL servers via a crafted
    certificate issued by a legitimate Certification
    Authority, a related issue to CVE-2009-2408.
    (CVE-2013-4248)

  - Integer overflow in the SdnToJewish function in jewish.c
    in the Calendar component in PHP before 5.3.26 and 5.4.x
    before 5.4.16 allows context-dependent attackers to
    cause a denial of service (application hang) via a large
    argument to the jdtojewish function. (CVE-2013-4635)

  - The mget function in libmagic/softmagic.c in the
    Fileinfo component in PHP 5.4.x before 5.4.16 allows
    remote attackers to cause a denial of service (invalid
    pointer dereference and application crash) via an MP3
    file that triggers incorrect MIME type detection during
    access to an finfo object. (CVE-2013-4636)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.oracle.com/sunsecurity/entry/cve_2013_4113_buffer_errors"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_php
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?00112bc0"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_php1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4120fb39"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_php2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?489d3873"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.17.5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:php");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/01");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^php$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.17.0.5.0", sru:"SRU 11.1.17.5.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : php\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "php");
