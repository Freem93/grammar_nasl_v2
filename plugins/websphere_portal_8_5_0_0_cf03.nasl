#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78742);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/06 17:22:03 $");

  script_cve_id(
    "CVE-2014-3500",
    "CVE-2014-3501",
    "CVE-2014-3502",
    "CVE-2014-4761",
    "CVE-2014-4808",
    "CVE-2014-4814",
    "CVE-2014-4821",
    "CVE-2014-5191",
    "CVE-2014-6125",
    "CVE-2014-6126",
    "CVE-2014-6215"
  );
  script_bugtraq_id(
    69038,
    69041,
    69046,
    69161,
    70322,
    70755,
    70756,
    70757,
    70758,
    70759,
    71728
  );
  script_osvdb_id(
    109500,
    109835,
    109836,
    109837,
    112833,
    113719,
    113720,
    113721,
    113722,
    113723,
    115587
  );

  script_name(english:"IBM WebSphere Portal 8.5.0 < 8.5.0 CF03 Multiple Vulnerabilities");
  script_summary(english:"Checks for the installed patch.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has web portal software installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Portal installed on the remote host is
affected by the multiple vulnerabilities :

  - Multiple vulnerabilities exist in the Apache Cordova
    component, including cross-application scripting,
    security bypass, and information disclosure.
    (CVE-2014-3500, CVE-2014-3501, CVE-2014-3502)

  - An information disclosure flaw exists that allows
    remote authenticated attackers to obtain credentials
    by reading HTML source code. (CVE-2014-4761)

  - An unspecified vulnerability exists that allows an
    authenticated attacker to execute arbitrary code on the
    system. (CVE-2014-4808)

  - A flaw exists that is caused by improper recursion
    detection during entity expansion. By tricking a user
    into opening a specially-crafted XML document, an
    attacker can cause the system to crash, resulting in a
    denial of service. (CVE-2014-4814)

  - An information disclosure vulnerability exists that
    allows a remote attacker to identify whether or not a
    file exists based on the web server error codes.
    (CVE-2014-4821)

  - A flaw exists in CKEditor in the Preview plugin that
    allows a cross-site scripting attack. The flaw exists
    due to 'plugins/preview/preview.html' not properly
    validating user-supplied input before returning it to
    users. This allows an attacker to send a specially
    crafted request designed to steal cookie-based
    authentication credentials. (CVE-2014-5191)

  - A cross-site request forgery vulnerability exists due
    to improper validation of user-supplied input. By
    tricking a user into visiting a malicious website, a
    remote attacker can perform cross-site scripting
    attacks, web cache poisoning, and other malicious
    activities. (CVE-2014-6125)

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input. A remote
    attacker can execute code within a victim's web browser
    within the context of the hosted site. This can lead to
    the compromise of the user's cookie-based authentication
    credentials. (CVE-2014-6126)

  - An unspecified cross-site scripting vulnerability exists
    due to improper validation of user input.
    (CVE-2014-4762)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21684649");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21684651");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_fixes_available_for_security_vulnerabilities_in_ibm_websphere_portal_cve_2014_4814_cve_2014_4808_cve_2014_4821_cve_2014_6125_cve_2014_6126?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e77e115");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_fixes_available_for_security_vulnerabilities_in_ckeditor_that_affect_ibm_websphere_portal_cve_2014_5191?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60595c5b");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21684650");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21684652");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_fixes_available_for_security_vulnerabilities_in_ibm_websphere_portal_cve_2014_3083_cve_2014_4761?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa26251e");
  script_set_attribute(attribute:"solution", value:
"IBM has published a cumulative fix (CF03) for WebSphere Portal 8.5.0.
Refer to IBM's advisory for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/30");

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
  ranges:make_list("8.5.0.0, 8.5.0.0"),
  fix:"CF03",
  severity:SECURITY_WARNING,
  xss:TRUE,
  xsrf:TRUE
);
