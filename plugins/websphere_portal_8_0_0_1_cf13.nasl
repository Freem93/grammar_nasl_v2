#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77533);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/13 21:07:14 $");

  script_cve_id("CVE-2011-1498", "CVE-2014-3102", "CVE-2014-4746", "CVE-2014-4760");
  script_bugtraq_id(46974, 69044, 69045, 69047);
  script_osvdb_id(71647, 109740, 109741, 109743);
  script_xref(name:"CERT", value:"153049");

  script_name(english:"IBM WebSphere Portal 8.x < 8.0.0.1 CF13 Multiple Vulnerabilities");
  script_summary(english:"Checks for installed patches.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has web portal software installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Portal on the remote host is affected by
multiple vulnerabilities :

  - An information disclosure vulnerability exists in the
    HttpClient component of the Apache HttpComponents
    library. An attacker can exploit this issue by
    sending a Proxy-Authorization header to retrieve a
    user's password. (CVE-2011-1498)

  - An unspecified cross-site scripting vulnerability
    exists due to improper validation of user input. An
    attacker can exploit this issue to execute code in
    the security context of a user's browser.
    (CVE-2014-3102)

  - An information disclosure vulnerability exists due to
    the returned error codes which an attacker can use to
    identify devices behind a firewall. (CVE-2014-4746)

  - An unspecified open redirect vulnerability exists that
    can allow an attacker to perform a phishing attack by
    enticing a user to click on a malicious URL.
    (CVE-2014-4760)");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21676776");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_fixes_available_for_vulnerability_in_apache_httpcomponents_httpclient_contained_in_ibm_websphere_portal_cve_2011_1498?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c0df724");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21680230");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_fixes_available_for_security_vulnerabilities_in_ibm_websphere_portal_multiple_cves1?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad660435");
  script_set_attribute(attribute:"solution", value:
"IBM has published a cumulative fix for WebSphere Portal 8.0.0.1
(CF13). Refer to IBM's advisory for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_portal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("websphere_portal_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Portal");
  exit(0);
}

include("websphere_portal_version.inc");

websphere_portal_check_version(
  ranges:make_list("8.0.0.0, 8.0.0.1"),
  fix:"CF13",
  severity:SECURITY_WARNING,
  xss:TRUE
);
