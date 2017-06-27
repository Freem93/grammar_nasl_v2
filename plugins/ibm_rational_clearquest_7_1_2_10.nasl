#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66172);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/03/12 15:08:55 $");

  script_cve_id("CVE-2012-5757");
  script_bugtraq_id(58631);
  script_osvdb_id(91578);

  script_name(english:"IBM Rational ClearQuest 7.1.x < 7.1.2.10 / 8.0.0.x < 8.0.0.6 Web Client Unspecified XSS (credentialed check)");
  script_summary(english:"Checks version of IBM Rational ClearQuest.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has software installed that is affected by a
cross-site scripting vulnerability."
  );
  script_set_attribute(attribute:"description", value:
"The remote host has a version of IBM Rational ClearQuest 7.1.x prior
to 7.1.2.10 / 8.0.0.x prior to 8.0.0.6 installed. It is, therefore,
potentially affected by an unspecified cross-site scripting
vulnerability related to the 'Web client' component. 

Note that only hosts with the server component 'Web client' deployed
are affected. Hosts with only the 'Desktop' components deployed are
not affected.");
  # Security bulletin
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21619993");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_clearquest_cross_site_scripting_xss_vulnerability_cve_2012_57573?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e51b27e");

  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Rational ClearQuest 7.1.2.10 / 8.0.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rational_clearquest");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies('ibm_rational_clearquest_installed.nasl');
  script_require_keys('installed_sw/IBM Rational ClearQuest', "Settings/ParanoidReport");

  exit(0);
}

include('ibm_rational_clearquest_version.inc');

rational_clearquest_check_version(
  fixes:make_nested_list(
    make_array("Min", "7.1.0.0", "Fix UI", "7.1.2.10", "Fix", "7.1210.0.167"),
    make_array("Min", "8.0.0.0", "Fix UI", "8.0.0.6",  "Fix", "8.6.0.710")),
  components:make_list("Web Client"),
  severity:SECURITY_WARNING,
  xss:TRUE
);
