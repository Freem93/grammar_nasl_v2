#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93026);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_cve_id("CVE-2016-2925");
  script_bugtraq_id(92180);
  script_osvdb_id(
    142228,
    142229,
    142244
  );
  script_xref(name:"IAVB", value:"2016-B-0135");

  script_name(english:"IBM WebSphere Portal 8.0.0.x < 8.0.0.1 CF21 Multiple Vulnerabilities");
  script_summary(english:"Checks for the installed patch.");

  script_set_attribute(attribute:"synopsis", value:
"The web portal software installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Portal installed on the remote Windows
host is 8.0.0.x prior to 8.0.0.1 CF21. It is, therefore, affected by
multiple vulnerabilities :

  - A cross-site scripting (XSS) vulnerability exists due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (CVE-2016-2925)

  - An information disclosure vulnerability exists due to
    a failure to set the 'Secure' flag for cookies
    transmitted via WAB forwarding, resulting in the
    information being transmitted in cleartext. A
    man-in-the-middle attacker can exploit this to disclose
    sensitive information. (VulnDB 142228)

  - An information disclose vulnerability exists in the
    portal model REST feeds due to exposing version
    information. An unauthenticated, remote attacker can
    exploit this to disclose sensitive version information.
    (VulnDB 142229)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24034497#CF21");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Portal 8.0.0.1 Cumulative Fix 21 (CF21) or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_portal");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("websphere_portal_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Portal");

  exit(0);
}

include("websphere_portal_version.inc");

websphere_portal_check_version(
  ranges:make_list("8.0.0.0, 8.0.0.1"),
  fix:"CF21",
  severity:SECURITY_WARNING,
  xss:TRUE
);
