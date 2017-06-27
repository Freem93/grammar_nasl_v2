#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84571);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/06 17:22:03 $");

  script_cve_id(
    "CVE-2015-0474",
    "CVE-2015-0493",
    "CVE-2015-1887",
    "CVE-2015-1917",
    "CVE-2015-1921",
    "CVE-2015-1944"
  );
  script_bugtraq_id(
    74134,
    74139,
    74705
  );
  script_osvdb_id(
    120669,
    120670,
    122328,
    123769,
    123770,
    123771
  );
  script_xref(name:"EDB-ID", value:"36788");

  script_name(english:"IBM WebSphere Portal 8.0.0.x < 8.0.0.1 CF17 Multiple Vulnerabilities");
  script_summary(english:"Checks for the installed patch.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has web portal software installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Portal installed on the remote host is
8.0.0.x prior to 8.0.0.1 CF17. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified flaw exists in the Outside In Filters
    subcomponent. An attacker, using a specially crafted
    DOCX file, can exploit this to corrupt memory, resulting
    in a denial of service or the execution of arbitrary
    code. (CVE-2015-0474)

  - An buffer overflow flaw exists in the Outside In Filters
    subcomponent due to 'ibpsd2.dll' not properly validating
    user-supplied input in PSD files. An attacker can
    exploit this to cause a denial of service or possibly
    execute arbitrary code. (CVE-2015-0493)

  - A flaw exists in the access control enforcement of the
    JCR component that allows a remote, unauthenticated
    attacker, using a specially crafted request, to gain
    access to potentially sensitive information.
    (CVE-2015-1887)

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
    
  - A flaw exists that allows a reflected cross-site
    scripting attack due to a failure to validate input
    before returning it back to the user. A remote attacker,
    using a crafted URL, can exploit this to execute code
    or HTML within the user's browser. (CVE-2015-1944)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24034497#CF17");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Portal 8.0.0.1 Cumulative Fix 17 (CF17) or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/07");

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
  ranges:make_list("8.0.0.0, 8.0.0.1"),
  fix:"CF17",
  severity:SECURITY_WARNING,
  xss:TRUE
);
