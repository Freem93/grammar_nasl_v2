#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100419);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/25 16:42:20 $");

  script_cve_id(
    "CVE-2017-3731",
    "CVE-2017-7409",
    "CVE-2017-7644",
    "CVE-2017-7945"
  );
  script_bugtraq_id(
    95813,
    98404,
    97953,
    98396
  );
  script_osvdb_id(
    151018,
    156061,
    156216,
    156650,
    156651
  );

  script_name(english:"Palo Alto Networks PAN-OS 6.1.x < 6.1.17 / 7.0.x < 7.0.15 Multiple Vulnerabilities");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Palo Alto Networks PAN-OS running on the remote host is
6.1.x prior to 6.1.17 or 7.0.x prior to 7.0.15. It is, therefore,
affected by multiple vulnerabilities :

  - An out-of-bounds read error exists when handling packets
    using the CHACHA20/POLY1305 or RC4-MD5 ciphers. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted truncated packets, to cause a denial
    of service condition. Note that this vulnerability only
    affects the 7.0 branch. (CVE-2017-3731)

  - A cross-site scripting (XSS) vulnerability exists in
    GlobalProtect due to improper validation of
    user-supplied input to unspecified request parameters
    before returning it to users. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. Note that this vulnerability only
    affects the 7.0 branch. (CVE-2017-7409)

  - A flaw exists in the web-based management interface due
    to improper permission checks that allows an
    authenticated, remote attacker to disclose sensitive
    information. (CVE-2017-7644)

  - An information disclosure vulnerability exists in the
    GlobalProtect external interface due to returning
    different error messages when handling login attempts
    with valid or invalid usernames. An unauthenticated,
    remote attacker can exploit this to enumerate valid
    user accounts. (CVE-2017-7945)

  - A denial of service vulnerability exists in the
    firewall when handling stale responses to authentication
    requests prior to selecting CHAP or PAP as the protocol.
    An unauthenticated, remote attacker can exploit this to
    cause the authentication process (authd) to stop
    responding. Note that this vulnerability only affects
    the 7.0 branch. (VulnDB 156216)");
  # https://www.paloaltonetworks.com/documentation/70/pan-os/pan-os-release-notes/pan-os-7-0-15-addressed-issues
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fe505ba3");
  # https://www.paloaltonetworks.com/documentation/61/pan-os/pan-os-release-notes/pan-os-6-1-17-addressed-issues
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9254ef1a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 6.1.17 / 7.0.15 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version");

  exit(0);
}

include("vcf.inc");

app_name = "Palo Alto Networks PAN-OS";

app_info = vcf::get_app_info(app:app_name, kb_ver:"Host/Palo_Alto/Firewall/Version", webapp:true);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  {"min_version" : "7.0.0", "max_version" : "7.0.14", "fixed_version" : "7.0.15" },
  {"min_version" : "6.1.0", "max_version" : "6.1.16", "fixed_version" : "6.1.17" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:true});
