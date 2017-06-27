#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81779);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/03/13 13:54:23 $");

  script_cve_id(
    "CVE-2010-4600",
    "CVE-2010-4601",
    "CVE-2010-4602",
    "CVE-2010-4603",
    "CVE-2011-1205"
  );
  script_bugtraq_id(45646, 45648, 47091);
  script_osvdb_id(69889, 69890, 70231, 70232, 73775);

  script_name(english:"IBM Rational ClearQuest 7.1.1.x < 7.1.1.4 / 7.1.2.x < 7.1.2.1 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks the version of IBM Rational ClearQuest.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple vulnerabilities.");
  script_set_attribute(
    attribute:"description", value:
"The remote host is running a version of IBM Rational ClearQuest
7.1.1.x prior to 7.1.1.4 / 7.1.2.x prior to 7.1.2.1 installed. It is,
therefore, affected by the following vulnerabilities :

  - An information disclosure vulnerability exists in the
    Dojo Toolkit that allows a remote attacker to read
    cookies. (CVE-2010-4600)

  - Multiple unspecified vulnerabilities exist.
    (CVE-2010-4601)

  - A security bypass vulnerability exists that allows a
    restricted user to view arbitrary records by modifying
    the record number in the URL for a RECORD action in the
    browser bookmark. (CVE-2010-4602)

  - A vulnerability exists due to improper processing of
    back reference fields that allows an authenticated
    attacker to cause a denial of service or other
    unspecified impacts. (CVE-2010-4603)
");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PM15146");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PM01811");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PM20172");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PM22186");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21470998");

  script_set_attribute(attribute:"solution", value:"
Upgrade to IBM Rational ClearQuest 7.1.1.4 / 7.1.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rational_clearquest");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies('ibm_rational_clearquest_installed.nasl');
  script_require_keys('installed_sw/IBM Rational ClearQuest');
  
  exit(0); 
}

include('ibm_rational_clearquest_version.inc');

rational_clearquest_check_version(
  fixes:make_nested_list(
    make_array("Min", "7.1.0.0", "Fix UI", "7.1.1.9", "Fix", "7.1109.0.176"),
    make_array("Min", "7.1.2.0", "Fix UI", "7.1.2.6", "Fix", "7.1206.0.141")),
  severity:SECURITY_HOLE,
  sqli:TRUE
);
