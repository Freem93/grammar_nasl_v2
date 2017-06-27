#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81781);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/03/13 13:54:23 $");

  script_cve_id("CVE-2013-5422");
  script_bugtraq_id(64340);
  script_osvdb_id(101027);

  script_name(english:"IBM Rational ClearQuest 8.0.0.x < 8.0.0.9 / 8.0.1.x < 8.0.1.2 Information Disclosure (credentialed check)");
  script_summary(english:"Checks the version of IBM Rational ClearQuest.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has software installed that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of IBM Rational ClearQuest 8.0.0.x
prior to 8.0.0.9 / 8.0.1.x prior to 8.0.1.2 installed. It is,
therefore, potentially affected by an unspecified information
disclosure vulnerability which allows an attacker to view database
names.

Note that this only affects the Web Client component when multiple
user databases are used.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21660036");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PM97698");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Rational ClearQuest 8.0.0.9 / 8.0.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/13");
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
    make_array("Min", "7.1.0.0", "Fix UI", "8.0.0.9", "Fix", "8.9.0.709"),
    make_array("Min", "8.0.1.0", "Fix UI", "8.0.1.2", "Fix", "8.102.0.411")),
  components:make_list("Web Client"),
  severity:SECURITY_WARNING,
  paranoid:TRUE   #only affects Web client component & multiple user databases must be used
);
