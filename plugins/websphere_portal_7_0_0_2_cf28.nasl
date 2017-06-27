#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74155);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/06 17:22:03 $");

  script_cve_id("CVE-2014-0949", "CVE-2014-0951", "CVE-2014-0958");
  script_bugtraq_id(67412, 67413, 67414);
  script_osvdb_id(107026, 107027, 107033);

  script_name(english:"IBM WebSphere Portal 7.0.0.x < 7.0.0.2 CF28 Multiple Vulnerabilities");
  script_summary(english:"Checks for the installed patch.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has web portal software installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Portal installed on the remote host is
affected by multiple vulnerabilities :

  - An unspecified denial of service vulnerability exists
    that allows a remote attacker to crash the host by
    sending a specially crafted web request. (CVE-2014-0949)

  - A cross-site scripting (XSS) vulnerability exists in the
    'FilterForm.jsp' script due to improper user input
    validation. An attacker can exploit the vulnerability to
    execute code in the security context of a user's browser
    to steal authentication cookies. (CVE-2014-0951)

  - An unspecified open redirect vulnerability exists that
    allows an attacker to perform a phishing attack by
    enticing a user to click on a malicious URL.
    (CVE-2014-0958)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21672572");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_fixes_available_for_security_vulnerabilities_in_ibm_websphere_portal_multiple_cves?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e5ca5ae");
  script_set_attribute(attribute:"see_also", value:"http://xforce.iss.net/xforce/xfdb/92624");
  script_set_attribute(attribute:"see_also", value:"http://xforce.iss.net/xforce/xfdb/92739");
  script_set_attribute(attribute:"solution", value:
"IBM has published a cumulative fix (CF28) for WebSphere Portal
7.0.0.2. Refer to IBM's advisory for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_portal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("websphere_portal_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Portal");

  exit(0);
}

include("websphere_portal_version.inc");

websphere_portal_check_version(
  ranges:make_list("7.0.0.0, 7.0.0.2"),
  fix:"CF28",
  severity:SECURITY_WARNING,
  xss:TRUE
);
