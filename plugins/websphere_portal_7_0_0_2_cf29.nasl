#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79691);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_cve_id(
    "CVE-2014-0114",
    "CVE-2014-0910",
    "CVE-2014-0949",
    "CVE-2014-0952",
    "CVE-2014-0953",
    "CVE-2014-0954",
    "CVE-2014-0956",
    "CVE-2014-0959",
    "CVE-2014-3083",
    "CVE-2014-3102",
    "CVE-2014-4746",
    "CVE-2014-4760",
    "CVE-2014-4761",
    "CVE-2014-4792",
    "CVE-2014-4808",
    "CVE-2014-4814",
    "CVE-2014-4821",
    "CVE-2014-6093",
    "CVE-2014-6215",
    "CVE-2014-8909",
    "CVE-2015-1943"
  );
  script_bugtraq_id(
    67121,
    67413,
    67417,
    67418,
    67419,
    67421,
    68011,
    69042,
    69044,
    69045,
    69047,
    69298,
    69734,
    70322,
    70755,
    70757,
    70758,
    71358,
    71728,
    73958
  );
  script_osvdb_id(
    106409,
    107027,
    107028,
    107030,
    107031,
    107032,
    107914,
    109740,
    109741,
    109742,
    109743,
    110186,
    111227,
    112833,
    113719,
    113720,
    113721,
    115000,
    115587,
    117951,
    125136
  );

  script_name(english:"IBM WebSphere Portal 7.0.0.x < 7.0.0.2 CF29 Multiple Vulnerabilities");
  script_summary(english:"Checks for the installed patch.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has web portal software installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Portal installed on the remote host is
7.0.0.x prior to 7.0.0.2 CF29. It is, therefore, affected by multiple
vulnerabilities :

  - A remote code execution vulnerability exists in the
    Apache Struts ClassLoader. A remote attacker can exploit
    this issue by manipulating the 'class' parameter of an
    ActionForm object to execute arbitrary code.
    (CVE-2014-0114)

  - A cross-site scripting vulnerability exists which allows
    a remote, authenticated attacker to inject arbitrary
    web script or HTML. (CVE-2014-0910)

  - An unspecified denial of service vulnerability exists
    that allows a remote attacker to crash the host by
    sending a specially crafted web request to cause a
    consumption of resources. (CVE-2014-0949)

  - A cross-site scripting vulnerability exists in the
    'boot_config.jsp' script due to improper validation of
    user-supplied input. An attacker can exploit this issue
    to execute arbitrary script code in the security context
    of a user's browser to steal authentication cookies.
    (CVE-2014-0952)

  - An unspecified cross-site scripting vulnerability exists
    due to improper validation of user-supplied input.
    (CVE-2014-0953)

  - A privilege escalation vulnerability exists in the Web
    Content Viewer portlet due to improper handling of JSP
    includes. A remote attacker can exploit this issue to
    obtain sensitive information, cause a denial of service,
    or control the request dispatcher by sending a specially
    crafted URL request. (CVE-2014-0954)

  - An unspecified cross-site scripting vulnerability exists
    due to improper validation of user-supplied input. An
    attacker can exploit this issue to execute arbitrary
    script code in the security context of a user's web
    browser to steal authentication cookies. (CVE-2014-0956)

  - An unspecified denial of service vulnerability exists
    that allows an authenticated attacker to cause a
    successful login to loop back to the login page
    indefinitely. (CVE-2014-0959)

  - An unspecified information disclosure vulnerability
    exists which allows a remote attacker to gain access to
    sensitive information. (CVE-2014-3083)

  - An unspecified cross-site scripting vulnerability
    exists due to improper validation of user-supplied
    input. An attacker can exploit this issue to execute
    arbitrary script code in the security context of a
    user's browser. (CVE-2014-3102)

  - An information disclosure vulnerability exists due to
    the returned error codes which an attacker can use to
    identify devices behind a firewall. (CVE-2014-4746)

  - An unspecified open redirect vulnerability exists that
    allows an attacker to perform a phishing attack by
    enticing a user to click on a malicious URL.
    (CVE-2014-4760)

  - An information disclosure vulnerability exists which
    allows a remote, authenticated attacker to gain access
    to sensitive information, such as user credentials,
    through certain HTML pages. (CVE-2014-4761)

  - An unrestricted file upload vulnerability exists which
    allows a remote, authenticated attacker to upload large
    files, potentially resulting in a denial of service.
    (CVE-2014-4792)

  - An unspecified vulnerability exists that allows an
    authenticated attacker to execute arbitrary code on the
    system. (CVE-2014-4808)

  - A flaw exists due to improper recursion detection during
    entity expansion. A remote attacker, via a specially
    crafted XML document, can cause the system to crash,
    resulting in a denial of service. (CVE-2014-4814)

  - An information disclosure vulnerability exists that
    allows a remote attacker to identify whether or not a
    file exists based on the web server error codes.
    (CVE-2014-4821)

  - An unspecified cross-site scripting vulnerability exists
    that allows a remote, authenticated attacker to execute
    arbitrary code via a specially crafted URL.
    (CVE-2014-6093)

  - An unspecified reflected cross-site scripting
    vulnerability exists due to improper validation of
    user-supplied input. A remote attacker can exploit this
    flaw using a specially crafted URL to execute arbitrary
    script code in a user's web browser within the security
    context of the hosting website. This allows an attacker
    to steal a user's cookie-based authentication
    credentials. (CVE-2014-6215)

  - An unspecified reflected cross-site scripting
    vulnerability exists due to improper validation of
    user-supplied input. A remote attacker can exploit this
    flaw using a specially crafted URL to execute arbitrary
    script code in a user's web browser within the security
    context of the hosting website. This allows an attacker
    to steal a user's cookie-based authentication
    credentials. (CVE-2014-8909)

  - An unspecified flaw exists that is trigged when handling
    Portal requests. A remote attacker can exploit this to
    cause a consumption of CPU resources, resulting in a
    denial of service condition. (CVE-2015-1943)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21672572");
  # http://www-01.ibm.com/support/docview.wss?uid=swg24029452#CF029
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2a808243");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Portal 7.0.0.2 Cumulative Fix 29 (CF29) or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts ClassLoader Manipulation Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/03");

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
  fix:"CF29",
  severity:SECURITY_HOLE,
  xss:TRUE
);
