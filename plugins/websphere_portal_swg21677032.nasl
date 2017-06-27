#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77541);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_cve_id(
    "CVE-2014-3054",
    "CVE-2014-3055",
    "CVE-2014-3056",
    "CVE-2014-3057"
  );
  script_bugtraq_id(68924, 68925, 68928, 68929);
  script_osvdb_id(109573, 109574, 109575, 109576);

  script_name(english:"IBM WebSphere Portal 8.0.0.x Unified Task List Portlet Multiple Vulnerabilities (PI18909)");
  script_summary(english:"Checks for an installed patch.");

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
  # https://www.ibm.com/blogs/psirt/ibm-security-bulletin-fixes-available-for-security-vulnerabilities-in-ibm-websphere-portal-related-to-unified-task-list-utl-portlet-cve-2014-3054-cve-2014-3055-cve-2014-3056-cve-2014-3057/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77124e50");
  script_set_attribute(attribute:"solution", value:
"Upgrade to 8.0.0.1 CF12 (PI14791) and then apply Interim Fix PI18909
or 8.0.0.1 CF13 (PI17735) or apply the workaround. Refer to IBM's
advisory for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
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
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("websphere_portal_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Portal");
  script_require_ports(139, 445);
  exit(0);
}

include("websphere_portal_version.inc");

portlets = make_array();

paa = "Unified Task List (UTL)";
portlets[paa]["Cell File"] = "\PA_WPF.ear\unifiedtasklist.war\utl-version.properties";
portlets[paa]["WP Ranges"] = make_list("8.0.0.0, 8.0.0.1");

websphere_portal_check_version(
  ranges:make_list("8.0.0.0, 8.0.0.1, CF12"),
  fix:"PI14791",
  portlets:portlets,
  req_vuln_portlets:make_list(paa),
  severity:SECURITY_HOLE,
  sqli:TRUE,
  xss: TRUE
);
