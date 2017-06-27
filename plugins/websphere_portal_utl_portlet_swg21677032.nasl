#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77542);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/13 21:07:14 $");

  script_cve_id(
    "CVE-2014-3054",
    "CVE-2014-3055",
    "CVE-2014-3056",
    "CVE-2014-3057"
  );
  script_bugtraq_id(68924, 68925, 68928, 68929);
  script_osvdb_id(109573, 109574, 109575, 109576);

  script_name(english:"IBM WebSphere Portal 7.0.0.x Unified Task List Portlet < 6.0.1 Multiple Vulnerabilities (PI18909)");
  script_summary(english:"Checks for installed portlet.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has web portal software installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Portal on the remote host is affected by
multiple vulnerabilities in the Unified Task List (UTL) portlet :

  - An unspecified open redirect vulnerability exists that
    allows a remote attacker to perform a phishing attack
    by enticing a user to click a malicious URL.
    (CVE-2014-3054)

  - A SQL injection vulnerability exists that allows a
    remote attacker who is a trusted user to manipulate or
    inject SQL queries into the back-end database.
    (CVE-2014-3055)

  - An information disclosure vulnerability exists that
    allows remote attackers to view environment variables
    and certain JAR files along with the versions.
    (CVE-2014-3056)

  - A cross-site scripting vulnerability exists that allows
    a remote attacker to execute arbitrary code in a user's
    browser. (CVE-2014-3057)");

  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21677032");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_fixes_available_for_security_vulnerabilities_in_ibm_websphere_portal_related_to_unified_task_list_utl_portlet_cve_2014_3054_cve_2014_3055_cve_2014_3056_cve_2014_3057?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc07a8d4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Unified Task List portlet 6.0.1 or later. Refer to IBM's
advisory for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_portal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("websphere_portal_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Portal");
  script_require_ports(139, 445);
  exit(0);
}

include("websphere_portal_version.inc");

paa_ver = UNKNOWN_VER;
paa_fix = "6.0.1";

paa = "Unified Task List";
portlets[paa]["Fixed Version"] = "6.0.1";
portlets[paa]["File"]  = "\..\paa\unifiedtasklist\components\unifiedtasklist\version\checklists.common.component";
portlets[paa]["Version Regex"] = 'spec-version="([0-9\\.]+)"\\s*/>';
portlets[paa]["WP Ranges"] = make_list("7.0.0.0, 7.0.0.2");


websphere_portal_check_version(
  portlets:portlets,
  severity:SECURITY_HOLE,
  xss     :TRUE,
  sqli    :TRUE
);
