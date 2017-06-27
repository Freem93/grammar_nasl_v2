#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80749);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/22 14:23:02 $");

  script_cve_id("CVE-2011-3389", "CVE-2012-0845", "CVE-2012-0876", "CVE-2012-1150");

  script_name(english:"Oracle Solaris Third-Party Patch Update : python (multiple_vulnerabilities_in_python) (BEAST)");
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

  - The SSL protocol, as used in certain configurations in
    Microsoft Windows and Microsoft Internet Explorer,
    Mozilla Firefox, Google Chrome, Opera, and other
    products, encrypts data by using CBC mode with chained
    initialization vectors, which allows man-in-the-middle
    attackers to obtain plaintext HTTP headers via a
    blockwise chosen-boundary attack (BCBA) on an HTTPS
    session, in conjunction with JavaScript code that uses
    (1) the HTML5 WebSocket API, (2) the Java URLConnection
    API, or (3) the Silverlight WebClient API, aka a 'BEAST'
    attack. (CVE-2011-3389)

  - SimpleXMLRPCServer.py in SimpleXMLRPCServer in Python
    before 2.6.8, 2.7.x before 2.7.3, 3.x before 3.1.5, and
    3.2.x before 3.2.3 allows remote attackers to cause a
    denial of service (infinite loop and CPU consumption)
    via an XML-RPC POST request that contains a smaller
    amount of data than specified by the Content-Length
    header. (CVE-2012-0845)

  - The XML parser (xmlparse.c) in expat before 2.1.0
    computes hash values without restricting the ability to
    trigger hash collisions predictably, which allows
    context-dependent attackers to cause a denial of service
    (CPU consumption) via an XML file with many identifiers
    with the same value. (CVE-2012-0876)

  - Python before 2.6.8, 2.7.x before 2.7.3, 3.x before
    3.1.5, and 3.2.x before 3.2.3 computes hash values
    without restricting the ability to trigger hash
    collisions predictably, which allows context-dependent
    attackers to cause a denial of service (CPU consumption)
    via crafted input to an application that maintains a
    hash table. (CVE-2012-1150)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_python
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a4e8993"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:python");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/10");
  script_set_attribute(attribute:"in_the_news", value:"true");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^python-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "python");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.0.0.0.0", sru:"SRU 0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : python\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "python");
