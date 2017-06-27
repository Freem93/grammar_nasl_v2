#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74156);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/06 17:22:03 $");

  script_cve_id(
    "CVE-2014-0050",
    "CVE-2014-0949",
    "CVE-2014-0951",
    "CVE-2014-0952",
    "CVE-2014-0953",
    "CVE-2014-0954",
    "CVE-2014-0955",
    "CVE-2014-0956",
    "CVE-2014-0958",
    "CVE-2014-0959"
  );
  script_bugtraq_id(
    65400,
    67412,
    67413,
    67414,
    67415,
    67417,
    67418,
    67419,
    67421,
    69042
  );
  script_osvdb_id(
    102945,
    107026,
    107027,
    107028,
    107029,
    107030,
    107031,
    107032,
    107033,
    109742
  );

  script_xref(name:"EDB-ID", value:"31615");

  script_name(english:"IBM WebSphere Portal 8.x < 8.0.0.1 CF12 Multiple Vulnerabilities");
  script_summary(english:"Checks for installed patches.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has web portal software installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Portal on the remote host is affected by
multiple vulnerabilities :

  - A denial of service vulnerability exists in the Apache
    Commons FileUpload library that allows an attacker to
    cause the application to enter an infinite loop.
    (CVE-2014-0050)

  - An unspecified denial of service vulnerability exists
    that allows a remote attacker to crash the host by
    sending a specially crafted web request.
    (CVE-2014-0949)

  - A cross-site scripting (XSS) vulnerability exists in the
    'FilterForm.jsp' script due to improper user input
    validation. (CVE-2014-0951)

  - An XSS vulnerability exists in the 'boot_config.jsp'
    script due to improper user input validation.
    (CVE-2014-0952)

  - An unspecified XSS vulnerability exists due to improper
    validation of user input. (CVE-2014-0953)

  - A privilege escalation vulnerability exists in the Web
    Content Viewer portlet due to improper handling of JSP
    includes. A remote attacker can exploit this issue to
    obtain sensitive information, cause a denial of service,
    or control the request dispatcher by sending a specially
    crafted URL request. (CVE-2014-0954)

  - An XSS vulnerability exists in the Social Rendering
    feature due to improper validation of user input. Note
    that this only affects installs using IBM Connections
    with the Social Rendering feature. (CVE-2014-0955)

  - An unspecified XSS vulnerability exists due to improper
    validation of user input in a JSP script.
    (CVE-2014-0956)

  - An unspecified open redirect vulnerability exists that
    allows an attacker to perform a phishing attack by
    enticing a user to click on a malicious URL.
    (CVE-2014-0958)

  - An unspecified denial of service vulnerability exists
    that allows an authenticated attacker to cause a
    successful login to loop back to the login page
    indefinitely. (CVE-2014-0959)

An attacker can exploit the XSS vulnerabilities to execute code in the
security context of a user's browser in order to steal authentication
cookies.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21672572");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_fixes_available_for_vulnerability_in_apache_commons_fileupload_contained_in_ibm_websphere_portal_cve_2014_0050?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?12fd87aa");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21672575");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_fixes_available_for_security_vulnerabilities_in_ibm_websphere_portal_multiple_cves?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e5ca5ae");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21680230");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_fixes_available_for_security_vulnerabilities_in_ibm_websphere_portal_multiple_cves1?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad660435");
  script_set_attribute(attribute:"see_also", value:"http://xforce.iss.net/xforce/xfdb/92622");
  script_set_attribute(attribute:"see_also", value:"http://xforce.iss.net/xforce/xfdb/92624");
  script_set_attribute(attribute:"see_also", value:"http://xforce.iss.net/xforce/xfdb/92625");
  script_set_attribute(attribute:"see_also", value:"http://xforce.iss.net/xforce/xfdb/92626");
  script_set_attribute(attribute:"see_also", value:"http://xforce.iss.net/xforce/xfdb/92627");
  script_set_attribute(attribute:"see_also", value:"http://xforce.iss.net/xforce/xfdb/92628");
  script_set_attribute(attribute:"see_also", value:"http://xforce.iss.net/xforce/xfdb/92629");
  script_set_attribute(attribute:"see_also", value:"http://xforce.iss.net/xforce/xfdb/92739");
  script_set_attribute(attribute:"see_also", value:"http://xforce.iss.net/xforce/xfdb/92741");
  script_set_attribute(attribute:"solution", value:
"IBM has published a cumulative fix for WebSphere Portal 8.0.0.1
(CF12). Refer to IBM's advisory for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/13");
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
  ranges:make_list("8.0.0.0, 8.0.0.1"),
  fix:"CF12",
  severity:SECURITY_HOLE,
  xss:TRUE
);
