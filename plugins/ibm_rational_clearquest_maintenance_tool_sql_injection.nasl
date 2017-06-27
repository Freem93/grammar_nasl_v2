#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59293);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/03/13 13:54:23 $");

  script_cve_id("CVE-2011-1390", "CVE-2012-0708");
  script_bugtraq_id(53170, 53483);
  script_osvdb_id(81443, 81815);

  script_name(english:"IBM Rational ClearQuest 7.1.1.x < 7.1.1.9 / 7.1.2.x < 7.1.2.6 / 8.0.0.x < 8.0.0.2 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks the version of IBM Rational ClearQuest.");

  script_set_attribute(
    attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description", value:
"The remote host is running a version of IBM Rational ClearQuest
7.1.1.x prior to 7.1.1.9 / 7.1.2.x prior to 7.1.2.6 / 8.0.0.x prior
to 8.0.0.2 installed. It is, therefore, affected by the following
vulnerabilities :

  - A SQL injection vulnerability exists in the ClearQuest
    Maintenance tool when upgrading the user database. Note
    that the Maintenance tool must be able to directly
    connect to ClearQuest repositories to be exploitable.
    (CVE-2011-1390)
  
  - A heap-based buffer overflow vulnerability exists in the
    'RegisterSchemaRepoFromFileByDbSet' function of the
    CQOle ActiveX control (cqole.dll) due to improper
    parsing of parameters. Exploitation of this issue can
    result in arbitrary code execution. (CVE-2012-0708)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21594717");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21591705");
  script_set_attribute(
    attribute:"solution", value:
"Upgrade to IBM Rational ClearQuest 7.1.1.9 / 7.1.2.6 / 8.0.0.2 or
later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'IBM Rational ClearQuest CQOle Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rational_clearquest");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies('ibm_rational_clearquest_installed.nasl');
  script_require_keys('installed_sw/IBM Rational ClearQuest');
  
  exit(0); 
}

include('ibm_rational_clearquest_version.inc');

rational_clearquest_check_version(
  fixes:make_nested_list(
    make_array("Min", "7.1.0.0", "Fix UI", "7.1.1.9", "Fix", "7.1109.0.176"),
    make_array("Min", "7.1.2.0", "Fix UI", "7.1.2.6", "Fix", "7.1206.0.141"),
    make_array("Min", "8.0.0.0", "Fix UI", "8.0.0.2", "Fix", "8.2.0.680")),
  severity:SECURITY_HOLE,
  sqli:TRUE
);
