#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83872);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/19 18:10:50 $");

  script_cve_id(
    "CVE-2015-0493",
    "CVE-2015-1886",
    "CVE-2015-1899",
    "CVE-2015-1908",
    "CVE-2015-1917",
    "CVE-2015-1921",
    "CVE-2015-1944",
    "CVE-2015-1943"
  );
  script_bugtraq_id(
    74134,
    74173,
    74216,
    74218,
    74705
  );
  script_osvdb_id(
    120503,
    120670,
    121027,
    121028,
    122328,
    123770,
    123771,
    125136
  );
  script_xref(name:"EDB-ID", value:"36788");

  script_name(english:"IBM WebSphere Portal 8.5.0 < 8.5.0 CF06 Multiple Vulnerabilities");
  script_summary(english:"Checks for the installed patch.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has web portal software installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Portal installed on the remote host is
8.5.0 prior to 8.5.0 CF06. It is, therefore, affected by multiple
vulnerabilities :

  - An buffer overflow flaw exists in the Outside In Filters
    subcomponent due to 'ibpsd2.dll' not properly validating
    user-supplied input in PSD files. An attacker can
    exploit this to cause a denial of service or possibly
    execute arbitrary code. (CVE-2015-0493)

  - An unspecified flaw exists in the Remote Document
    Conversion Service (DCS) that allows a remote attacker
    to cause a denial of service. (CVE-2015-1886)

  - A flaw exists when handling a specially crafted request
    that allows a remote attacker to use too many available
    resources, resulting in a denial of service.
    (CVE-2015-1899)

  - A flaw exists that allows a reflected cross-site
    scripting attack due to a failure to validate input
    before returning it back to the user. A remote attacker,
    using a crafted URL, can exploit this to execute code
    or HTML within the user's browser. (CVE-2015-1908,
    CVE-2015-1944)

  - A cross-site scripting vulnerability exists in the
    Active Content Filtering component due to improperly
    validating user-supplied input. A remote attacker can
    exploit this by creating a specially crafted URL
    designed to execute script code in the victim's web
    browser. (CVE-2015-1917)

  - A flaw exists that allows a cross-site redirection
    attack due to a failure to validate certain unspecified
    input before returning it to the user. An attacker,
    using specially crafted URL, can exploit this to
    redirect victims to a website of the attacker's own
    choosing. (CVE-2015-1921)

  - An unspecified flaw exists that is trigged when handling
    Portal requests. A remote attacker can exploit this to
    cause a consumption of CPU resources, resulting in a
    denial of service condition. (CVE-2015-1943)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24037786");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Portal 8.5.0 Cumulative Fix 06 (CF06) or
later. Refer to the IBM advisory for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_portal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("websphere_portal_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Portal");

  exit(0);
}

include("websphere_portal_version.inc");

websphere_portal_check_version(
  ranges:make_list("8.5.0.0, 8.5.0.0"),
  fix:"CF06",
  severity:SECURITY_HOLE,
  xss:TRUE
);
