#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81783);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/20 14:03:01 $");

  script_cve_id(
    "CVE-2014-3101",
    "CVE-2014-3103",
    "CVE-2014-3104",
    "CVE-2014-3105",
    "CVE-2014-3106"
  );
  script_bugtraq_id(70032, 70033, 70036);
  script_osvdb_id(111644, 111645, 111646, 111647, 111648);

  script_name(english:"IBM Rational ClearQuest 7.1.x < 7.1.2.15 / 8.0.0.x < 8.0.0.12 / 8.0.1.x < 8.0.1.5 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks version of IBM Rational ClearQuest.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has software installed that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of IBM Rational ClearQuest 7.1.x prior
to 7.1.2.15 / 8.0.0.x prior to 8.0.0.12 / 8.0.1.x prior to 8.0.1.5
installed. It is, therefore, potentially affected by multiple
vulnerabilities :

  - A security bypass vulnerability exists due to an error
    in the login form which allows a remote attacker to
    perform brute-force attacks. (CVE-2014-3101)

  - A security bypass vulnerability exists due to the lack
    of the secure flag for the session cookie during an SSL
    session. (CVE-2014-3103)

  - A denial of service vulnerability exists due to improper
    parsing of recursion during entity expansion of XML
    documents. (CVE-2014-3104)

  - A user enumeration vulnerability exists in the Open
    Services for Lifecycle Collaboration (OSLC) due to
    different error messages being displayed when a user
    submits valid and invalid credentials. (CVE-2014-3105)

  - A security bypass vulnerability exists due to improper
    enforcement of the 'Local Access Only' ACL related to
    the Help Server Administrator system. (CVE-2014-3106)");
  # CVE-2014-3101
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21682946");
  # CVE-2014-3103
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21682947");
  # CVE-2014-3104
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21682942");
  # CVE-2014-3105
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21682949");
  # CVE-2014-3106
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21682950");

  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Rational ClearQuest 7.1.2.15 / 8.0.0.12 / 8.0.1.5 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rational_clearquest");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies('ibm_rational_clearquest_installed.nasl');
  script_require_keys('installed_sw/IBM Rational ClearQuest', "Settings/ParanoidReport");

  exit(0);
}

include('ibm_rational_clearquest_version.inc');

rational_clearquest_check_version(
  fixes:make_nested_list(
    make_array("Min", "7.1.0.0", "Fix UI", "7.1.2.15", "Fix", "7.1215.0.133"),
    make_array("Min", "8.0.0.0", "Fix UI", "8.0.0.12", "Fix", "8.12.0.719"),
    make_array("Min", "8.0.1.0", "Fix UI", "8.0.1.5",  "Fix", "8.105.0.412")),
  components:make_list("Web Client"),
  severity:SECURITY_WARNING
);
