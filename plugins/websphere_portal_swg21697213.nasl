#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82029);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/03/25 13:32:30 $");

  script_cve_id("CVE-2014-6214", "CVE-2015-0139", "CVE-2015-0177");
  script_bugtraq_id(73067, 73069, 73072);
  script_osvdb_id(119160, 119161, 119162);

  script_name(english:"IBM WebSphere Portal 8.0.0.x < 8.0.0.1 CF15 / 8.5.0.0 < 8.5.0.0 CF05 Multiple XSRF / XSS (PI34987, PI33329, PI35228)");
  script_summary(english:"Checks for an installed patch.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has web portal software installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Portal installed on the remote host is
8.0.0.x prior to 8.0.0.1 Cumulative Fix 15 / 8.5.0.0 prior to 8.5.0.0
Cumulative Fix 05. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified XSRF vulnerability exists due to improper
    validation of user-supplied input. A remote attacker can
    exploit this to perform authenticated actions, web cache
    poisoning, and other malicious activities.
    (CVE-2014-6214 / PI34987)

  - Multiple unspecified XSS vulnerabilities exist due to
    improper validation of user-supplied input. A remote
    attacker can exploit these issues to execute arbitrary
    script code in a user's browser. (CVE-2015-0139 /
    PI33329, CVE-2015-0177 / PI35228 )");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21697213");
  script_set_attribute(attribute:"solution", value:
"Customers with IBM WebSphere Portal 8.0.0.x should upgrade to 8.0.0.1
CF15 and then apply Interim Fixes PI34987 and PI33329. Customers with
IBM WebSphere Portal 8.5.0 should upgrade to 8.5.0 CF05 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_portal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("websphere_portal_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Portal");
  script_require_ports(139, 445);
  exit(0);
}

include("websphere_portal_version.inc");

fixes_for_85 = "PI33329, PI34987, PI35228";
fixes_for_80 = "PI33329, PI34987";

websphere_portal_check_version(
  checks:make_array(
    "8.5.0.0, 8.5.0.0, CF05", make_list(fixes_for_85),
    "8.0.0.0, 8.0.0.1, CF15", make_list(fixes_for_80)
  ),
  severity:SECURITY_WARNING,
  sqli:FALSE,
  xss: TRUE,
  xsrf: TRUE
);
