#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77534);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/09/05 10:46:41 $");

  script_cve_id("CVE-2014-4760");
  script_bugtraq_id(69047);
  script_osvdb_id(109740);

  script_name(english:"IBM WebSphere Portal 8.5.0 < 8.5.0 CF01 Open Redirect");
  script_summary(english:"Checks for installed patch.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has web portal software installed that is
affected by an open redirect vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Portal on the remote host is affected by
an unspecified open redirect vulnerability. This issue allows an
attacker to perform a phishing attack by enticing a user to click on a
malicious URL.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21672572");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_fixes_available_for_security_vulnerabilities_in_ibm_websphere_portal_multiple_cves?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e5ca5ae");
  script_set_attribute(attribute:"solution", value:
"IBM has published a cumulative fix for WebSphere Portal 8.5.0.0
(CF01). Refer to IBM's advisory for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_portal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("websphere_portal_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Portal");
  exit(0);
}

include("websphere_portal_version.inc");

websphere_portal_check_version(
  ranges:make_list("8.5.0.0, 8.5.0.0"),
  fix:"CF01",
  severity:SECURITY_WARNING
);
