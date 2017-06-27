#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(61565);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/03/12 15:08:55 $");

  script_cve_id(
    "CVE-2012-0744",
    "CVE-2012-2159",
    "CVE-2012-2161",
    "CVE-2012-2164",
    "CVE-2012-2165",
    "CVE-2012-2168",
    "CVE-2012-2169",
    "CVE-2012-2205"
  );
  script_bugtraq_id(53884, 54222, 55125);
  script_osvdb_id(82711, 82754, 83358, 83359, 84819, 84915, 84916, 84917);

  script_name(english:"IBM Rational ClearQuest 7.x < 7.1.2.7 / 8.0.0.x < 8.0.0.3 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks the version of IBM Rational ClearQuest.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has software installed that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of IBM Rational ClearQuest 7.x prior to
7.1.2.7 / 8.0.0.x prior to 8.0.0.3 installed. It is, therefore,
affected by the following vulnerabilities :

  - A cross-site scripting vulnerability exists that can
    be exploited by an attacker by tricking a victim into
    opening a specially crafted report. (CVE-2012-2205)

  - An information disclosure vulnerability exists that
    allows an attacker unauthorized access to password
    information. (CVE-2012-2165)

  - ClearQuest Web sometimes displays sensitive stack trace
    information in error messages. (CVE-2012-2168)

  - The ClearQuest Web Help component contains a reflected 
    cross-site scripting vulnerability. (CVE-2012-2161)

  - Some scripts inside the ClearQuest Web Help application 
    are vulnerable to open redirect attacks. (CVE-2012-2159)

  - The ClearQuest web client is subject to an elevated 
    privilege attack that allows an attacker access to the
    'Site Administration' menu. (CVE-2012-2164)

  - The ClearQuest web client file-upload functionality is
    affected by a cross-site scripting vulnerability that
    can be exploited by an authenticated user via the 'File 
    Description' field. (CVE-2012-2169)

  - Attackers can obtain potentially sensitive information
    via a request to a 'snoop', 'hello', 'ivt/', 'hitcount',
    'HitCount.jsp', 'HelloHTMLError.jsp', 'HelloHTML.jsp',
    'HelloVXMLError.jsp', 'HelloWMLError.jsp',
    'HellowWML.jsp' or 'cqweb/j_security_check' sample
    script. (CVE-2012-0744)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21606319");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21606385");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21605840");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21605839");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21605838");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21606318");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Rational ClearQuest 7.1.2.7 / 8.0.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/16");

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
    make_array("Min", "7.1.0.0", "Fix UI", "7.1.2.7", "Fix", "7.1207.0.127"),
    make_array("Min", "8.0.0.0", "Fix UI", "8.0.0.3", "Fix", "8.3.0.668")),
  severity:SECURITY_WARNING,
  xss:TRUE
);
