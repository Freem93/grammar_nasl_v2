#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81780);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/03/13 13:54:23 $");

  script_cve_id("CVE-2013-0598", "CVE-2013-3041");
  script_bugtraq_id(62654, 62656);
  script_osvdb_id(97801, 97802);

  script_name(english:"IBM Rational ClearQuest 7.1.x < 7.1.2.12 / 8.0.0.x < 8.0.0.8 / 8.0.1.x < 8.0.1.1 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks the version of IBM Rational ClearQuest.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has software installed that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of IBM Rational ClearQuest 7.1.x prior
to 7.1.2.12 / 8.0.0.x prior to 8.0.0.8 / 8.0.1.x prior to 8.0.1.1
installed. It is, therefore, potentially affected by multiple
vulnerabilities :

  - An unspecified cross-site request forgery (CSRF)
    vulnerability exists. (CVE-2013-0598)

  - An unspecified vulnerability allows for an attacker to
    perform JSON hijacking attacks. (CVE-2013-3041)

Note that these vulnerabilities only affect the Web Client component.");
  # CVE-2013-0598
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21648665");
  # CVE-2013-3041
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21648086");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Rational ClearQuest 7.1.2.12/ 8.0.0.8 / 8.0.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rational_clearquest");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies('ibm_rational_clearquest_installed.nasl');
  script_require_keys('installed_sw/IBM Rational ClearQuest', "Settings/ParanoidReport");

  exit(0);
}

include('ibm_rational_clearquest_version.inc');

rational_clearquest_check_version(
  fixes:make_nested_list(
    make_array("Min", "7.1.0.0", "Fix UI", "7.1.2.12", "Fix", "7.1212.0.162"),
    make_array("Min", "8.0.0.0", "Fix UI", "8.0.0.8",  "Fix", "8.8.0.706"),
    make_array("Min", "8.0.1.0", "Fix UI", "8.0.1.1",  "Fix", "8.101.0.407")),
  components:make_list("Web Client"),
  severity:SECURITY_WARNING,
  xsrf:TRUE
);
