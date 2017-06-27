#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78740);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/09/06 13:39:48 $");

  script_cve_id(
    "CVE-2014-0952",
    "CVE-2014-0956",
    "CVE-2014-4808",
    "CVE-2014-4814",
    "CVE-2014-4821",
    "CVE-2014-6215",
    "CVE-2014-8909",
    "CVE-2015-1943",
    "CVE-2016-2925"
  );
  script_bugtraq_id(
    67417,
    67419,
    70755,
    70757,
    70758,
    71728,
    73958
  );
  script_osvdb_id(
    107031,
    107032,
    113719,
    113720,
    113721,
    115587,
    117951,
    125136,
    142244
  );
  script_xref(name:"IAVB", value:"2016-B-0135");

  script_name(english:"IBM WebSphere Portal 6.1.5.x < 6.1.5.3 CF27 Multiple Vulnerabilities");
  script_summary(english:"Checks for the installed patch.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has web portal software installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Portal installed on the remote host is
6.1.5.x prior to 6.1.5.3 CF27. It is, therefore, affected by multiple
vulnerabilities :

  - A cross-site scripting vulnerability exists in the
    'boot_config.jsp' script due to improper validation of
    user-supplied input. An attacker can exploit this issue
    to execute arbitrary script code in the security context
    of a user's browser to steal authentication cookies.
    (CVE-2014-0952)

  - An unspecified cross-site scripting vulnerability exists
    due to improper validation of user-supplied input. An
    attacker can exploit this issue to execute arbitrary
    script code in the security context of a user's web
    browser to steal authentication cookies. (CVE-2014-0956)

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
    denial of service condition. (CVE-2015-1943)

  - An unspecified reflected cross-site scripting
    vulnerability exists due to improper validation of
    user-supplied input. A remote attacker can exploit this
    flaw using a specially crafted URL to execute arbitrary
    script code in a user's web browser within the security
    context of the hosting website. This allows an attacker
    to steal a user's cookie-based authentication
    credentials. (CVE-2016-2925)");

  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21684651");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_fixes_available_for_security_vulnerabilities_in_ibm_websphere_portal_cve_2014_4814_cve_2014_4808_cve_2014_4821_cve_2014_6125_cve_2014_6126?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e77e115");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg21672572");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Portal 6.1.5.3 Cumulative Fix 27 (CF27) or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_portal");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  ranges:make_list("6.1.5.0, 6.1.5.3"),
  fix:"CF27",
  severity:SECURITY_WARNING,
  xss:TRUE
);
