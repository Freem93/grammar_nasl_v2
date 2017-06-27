#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63323);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/03/12 15:08:55 $");

  script_cve_id("CVE-2012-4839", "CVE-2012-5765");
  script_bugtraq_id(56946);
  script_osvdb_id(88445, 88446);

  script_name(english:"IBM Rational ClearQuest 7.1.x < 7.1.2.9 / 8.0.0.x < 8.0.0.5 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks the version of IBM Rational ClearQuest.");

  script_set_attribute(
    attribute:"synopsis", value:
"The remote host has software installed that is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description", value:
"The remote host has a version of IBM Rational ClearQuest 7.1.x prior
to 7.1.2.9 / 8.0.0.x prior to 8.0.0.5 installed. It is, therefore,
affected by the following vulnerabilities :

  - An unspecified input validation error exists related to
    the Open Services for Lifecycle Collaboration (OSLC)
    system that can allow cross-site scripting attacks. Note
    that this issue only affects systems if the 'CQ Web
    Server' is deployed. This vulnerability only affects the
    7.1.2.x versions of ClearQuest. (CVE-2012-4839)

  - An unspecified input validation error exists that can
    allow sensitive information to be disclosed via SQL
    error messages. (CVE-2012-5765 / PM72905)"
  );
  # Security bulletin 
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21620342");
  # Security bulletin 
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21620048");
  # Fix packs availability notice
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21620296");

  script_set_attribute(attribute:"solution", value:"Upgrade to IBM Rational ClearQuest 7.1.2.9 / 8.0.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/21");

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
    make_array("Min", "7.1.0", "Fix UI", "7.1.2.9", "Fix", "7.1209.0.148"),
    make_array("Min", "8.0.0", "Fix UI", "8.0.0.5", "Fix", "8.5.0.691")),
  components:make_list("Web Client"),
  severity:SECURITY_WARNING
);
