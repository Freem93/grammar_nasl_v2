#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73385);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/23 22:03:56 $");

  script_cve_id("CVE-2014-0828", "CVE-2014-0901");
  script_bugtraq_id(66556, 66559);
  script_osvdb_id(105206, 105207);

  script_name(english:"IBM WebSphere Portal 8.0.0.1 CF11 Multiple XSS");
  script_summary(english:"Checks for installed patches.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has web portal software installed that is
affected by multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Portal on the remote host is affected by
multiple cross-site scripting (XSS) vulnerabilities :

  - An XSS vulnerability exists in the Web Content Manager
    user interface. (CVE-2014-0828)

  - An XSS vulnerability exists in the Social Rendering
    feature of the IBM Connections integration.
    (CVE-2014-0901)

An attacker can exploit these vulnerabilities to execute code in the
security context of a user's browser to steal authentication cookies.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21667016");
  script_set_attribute(attribute:"see_also", value:"http://xforce.iss.net/xforce/xfdb/90566");
  script_set_attribute(attribute:"see_also", value:"http://xforce.iss.net/xforce/xfdb/91398");

  script_set_attribute(attribute:"solution", value:
"IBM has published a cumulative fix for WebSphere Portal 8.0.0.1
(CF11). Refer to IBM's advisory for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_portal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("websphere_portal_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Portal");
  exit(0);
}

include("websphere_portal_version.inc");

websphere_portal_check_version(
  ranges:make_list("8.0.0.0, 8.0.0.1"),
  fix:"CF11",
  severity:SECURITY_WARNING,
  xss:TRUE
);
