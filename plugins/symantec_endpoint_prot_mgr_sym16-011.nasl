#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91894);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/04/17 14:16:27 $");

  script_cve_id(
    "CVE-2015-8801",
    "CVE-2016-3647",
    "CVE-2016-3648",
    "CVE-2016-3649",
    "CVE-2016-3650",
    "CVE-2016-3651",
    "CVE-2016-3652",
    "CVE-2016-3653",
    "CVE-2016-5304",
    "CVE-2016-5305",
    "CVE-2016-5306",
    "CVE-2016-5307"
  );
  script_bugtraq_id(
    91432,
    91433,
    91440,
    91441,
    91442,
    91443,
    91444,
    91445,
    91446,
    91447,
    91448,
    91449
  );
  script_osvdb_id(
    140673,
    140674,
    140675,
    140757,
    140758,
    140759,
    140760,
    140761,
    140762,
    140763,
    140764,
    140765
  );
  script_xref(name:"EDB-ID", value:"40041");

  script_name(english:"Symantec Endpoint Protection Manager 12.1.x < 12.1 RU6 MP5 Multiple Vulnerabilities (SYM16-011)");
  script_summary(english:"Checks the SEPM version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Symantec Endpoint Protection Manager installed on the
remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Endpoint Protection Manager (SEPM) installed
on the remote host is prior to 12.1 RU6 MP5. It is, therefore,
affected by the following vulnerabilities :

  - A race condition exists in the SEP client that allows a
    local attacker to bypass security restrictions,
    resulting in the ability to download or upload files on
    the client system. (CVE-2015-8801)

  - A server-side request forgery vulnerability exists in
    the authentication interface that allows an attacker to
    bypass access controls and scan unauthorized content on
    the internal network. (CVE-2016-3647)

  - An unspecified flaw exists that allows an attacker to
    bypass lock threshold limits, resulting in the ability 
    to recover management console passwords using
    brute-force methods. (CVE-2016-3648)

  - An unspecified flaw exists when handling GET object
    requests that allows an attacker to disclose information
    related to valid administrator accounts. (CVE-2016-3649)

  - An unspecified flaw exists that allows an attacker to
    disclose server credentials. (CVE-2016-3650)

  - An unspecified flaw exists related to PHP JSESSIONID
    that allows an attacker to execute arbitrary code.
    (CVE-2016-3651)

  - Multiple cross-site scripting vulnerabilities exist due
    to improper validation of user-supplied input to the
    'createModalDialogFromURL', 'createWindowFromURL',
    'createWindowFromForm', and 'createIEWindowFromForm'
    parameters in the notificationpopup.php script. An
    unauthenticated, remote attacker can exploit these
    issues, via a specially crafted request, to execute
    arbitrary script code in a user's browser session.
    (CVE-2016-3652)

  - A cross-site request forgery vulnerability exists in the
    sr-save.php script due to a failure to require multiple
    steps, explicit confirmation, or a unique token when
    performing certain sensitive actions. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted link, to cause a user to send schedule
    reports. (CVE-2016-3653)

  - A flaw exists in the externalurl.php script due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted link, to redirect a user to an
    arbitrary website. (CVE-2016-5304)

  - An unspecified flaw exists in a PHP script that allows
    an attacker to conduct DOM-based link manipulation.
    (CVE-2016-5305)

  - An information disclosure vulnerability exists due to a
    failure to enable HTTP Strict Transport Security on port
    8445. (CVE-2016-5306)

  - A directory traversal vulnerability exists in the
    management console that allows an attacker to access
    files and directories on the web root. (CVE-2016-5307)");
  # https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160628_01
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ff09b0f");
  # https://googleprojectzero.blogspot.com/2016/06/how-to-compromise-enterprise-endpoint.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a965f2f9");
  # http://hyp3rlinx.altervista.org/advisories/SYMANTEC-SEPM-MULTIPLE-VULNS.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0891bf6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Endpoint Protection Manager version 12.1 RU6 MP5
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection_manager");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("symantec_endpoint_prot_mgr_installed.nasl");
  script_require_keys("installed_sw/Symantec Endpoint Protection Manager");

  exit(0);
}

include("vcf.inc");

# Define constraints for version check
constraints = [
  {
    "fixed_version" : "12.1.7004.6500",
    "min_version"   : "12.1"
  }
];

# Get application info
app_info = vcf::get_app_info(app:'Symantec Endpoint Protection Manager', win_local:TRUE);

# Do version check using app_info
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{"xss":TRUE, "xsrf":TRUE});
