#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79216);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_cve_id(
    "CVE-2014-0114",
    "CVE-2014-3083",
    "CVE-2014-4761",
    "CVE-2014-4762",
    "CVE-2014-4792",
    "CVE-2014-6093"
  );
  script_bugtraq_id(67121, 69298, 69733, 69734, 70322, 71358);
  script_osvdb_id(106409, 110186, 111226, 111227, 112833, 115000);

  script_name(english:"IBM WebSphere Portal 8.5.0 < 8.5.0 CF02 Multiple Vulnerabilities");
  script_summary(english:"Checks for the installed patch.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has web portal software installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Portal installed on the remote host is
affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in the
    Apache Struts ClassLoader. A remote attacker can exploit
    this issue by manipulating the 'class' parameter of an
    ActionForm object to execute arbitrary code.
    (CVE-2014-0114)

  - An unspecified information disclosure vulnerability
    exists which allows a remote attacker to gain access to
    sensitive information. (CVE-2014-3083)

  - An information disclosure vulnerability exists which
    allows a remote, authenticated attacker to gain access
    to sensitive information, such as user credentials,
    through certain HTML pages. (CVE-2014-4761)

  - An unspecified cross-site scripting vulnerability exists
    due to improper validation of user input. This can be
    exploited by a remote, authenticated attacker to execute
    code in the security context of a user's browser.
    (CVE-2014-4762)

  - An unrestricted file upload vulnerability exists which
    allows a remote, authenticated attacker to upload large
    files, potentially resulting in a denial of service.
    (CVE-2014-4792)

  - An unspecified cross-site scripting vulnerability exists
    that allows remote, authenticated attackers to execute
    arbitrary code via a specially crafted URL.
    (CVE-2014-6093)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21684652");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_fixes_available_for_security_vulnerabilities_in_ibm_websphere_portal_cve_2014_3083_cve_2014_4761?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa26251e");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21681998");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_fixes_available_for_security_vulnerabilities_in_ibm_websphere_portal_cve_2014_4762_cve_2014_4792?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11287c08");
  script_set_attribute(attribute:"solution", value:
"IBM has published a cumulative fix (CF02) for WebSphere Portal
8.5.0.0. Refer to IBM's advisory for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts ClassLoader Manipulation Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");

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
  fix:"CF02",
  severity:SECURITY_HOLE,
  xss:TRUE
);
