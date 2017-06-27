#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86245);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/07/18 15:54:01 $");

  script_cve_id(
    "CVE-2014-3513",
    "CVE-2014-3566",
    "CVE-2014-3567",
    "CVE-2014-3568",
    "CVE-2014-6394",
    "CVE-2015-0248",
    "CVE-2015-0251",
    "CVE-2015-3185",
    "CVE-2015-5909",
    "CVE-2015-5910"
  );
  script_bugtraq_id(
    70100,
    70574,
    70584,
    70585,
    70586,
    74259,
    74260,
    75965
  );
  script_osvdb_id(
    111769,
    113251,
    113373,
    113374,
    113377,
    120099,
    120121,
    123123,
    127609,
    127610
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-09-16-2");
  script_xref(name:"CERT", value:"577193");

  script_name(english:"Apple Xcode < 7.0 (Mac OS X) (POODLE)");
  script_summary(english:"Checks the version of Xcode.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has an application installed that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Xcode installed on the remote Mac OS X host is
prior to 7.0. It is, therefore, affected by the multiple
vulnerabilities :

  - A memory leak issue exists in file d1_srtp.c related to
    the DTLS SRTP extension handling and specially crafted
    handshake messages. An attacker can exploit this to 
    cause denial of service condition. (CVE-2014-3513)

  - A man-in-the-middle (MitM) information disclosure
    vulnerability, known as POODLE, exists due to the way
    SSL 3.0 handles padding bytes when decrypting messages
    encrypted using block ciphers in cipher block chaining
    (CBC) mode. A MitM attacker can decrypt a selected byte
    of a cipher text in as few as 256 tries if they are able
    to force a victim application to repeatedly send the
    same data over newly created SSL 3.0 connections.
    (CVE-2014-3566)

  - A memory leak issue exists in file t1_lib.c related to
    session ticket handling. An attacker can exploit this to 
    cause denial of service condition. (CVE-2014-3567)

  - An error exists related to the build configuration
    process and the 'no-ssl3' build option that allows
    servers and clients to process insecure SSL 3.0
    handshake messages. (CVE-2014-3568)

  - A directory traversal vulnerability exists in send.js
    due to improper sanitization of user-supplied input.
    A remote, unauthenticated attacker can exploit this, via
    a specially crafted request, to access arbitrary files
    outside of the restricted path. (CVE-2014-6394)

  - A denial of service vulnerability exists in the
    mod_dav_svn and svnserve servers of Apache Subversion. A
    remote, unauthenticated attacker can exploit this, via a
    crafted combination of parameters, to cause the current
    process to abort through a failed assertion.
    (CVE-2015-0248)

  - A flaw exists in the mod_dav_svn server of Apache
    Subversion. A remote, authenticated attacker can exploit
    this, via a crafted HTTP request sequence, to spoof an
    'svn:author' property value. (CVE-2015-0251)

  - A flaw exists in the Apache HTTP Server due to the
    ap_some_auth_required() function in file request.c not
    properly handling Require directive associations. A
    remote, unauthenticated attacker can exploit this to
    bypass access restrictions, by leveraging a module that
    relies on the 2.2 API behavior. (CVE-2015-3185)

  - A flaw exists in the IDE Xcode server due to improper
    restriction of access to the repository email lists. A
    remote, unauthenticated attacker can exploit this to
    access sensitive build information, by leveraging
    incorrect notification delivery. (CVE-2015-5909)

  - A flaw exists in the IDE Xcode server due to the
    transmission of server information in cleartext. A
    remote, man-in-the-middle attacker can exploit this to
    access sensitive information. (CVE-2015-5910)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-ca/HT205217");
  # http://lists.apple.com/archives/security-announce/2015/Sep/msg00002.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9042c568");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Xcode version 7.0, which is available for OS X
version 10.10.4 (Yosemite) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/02");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:apple:xcode");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_xcode_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Apple Xcode");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item_or_exit("Host/MacOSX/Version");

# Patch is only available for OS X 10.10.4 and later
if (ereg(pattern:"Mac OS X 10\.([0-9]\.[0-9]|10\.[0-3]$)", string:os))
  audit(AUDIT_OS_NOT, "Mac OS X 10.10.4 or above");

appname = "Apple Xcode";

install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
path = install["path"];
ver = install["version"];

fix = '7.0';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(port:0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver, path);
