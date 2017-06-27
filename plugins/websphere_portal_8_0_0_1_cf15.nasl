#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82850);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/20 14:02:08 $");

  script_cve_id(
    "CVE-2012-6153",
    "CVE-2014-3577",
    "CVE-2014-4808",
    "CVE-2014-4814",
    "CVE-2014-4821",
    "CVE-2014-5191",
    "CVE-2014-6171",
    "CVE-2014-6193",
    "CVE-2014-8902"
  );
  script_bugtraq_id(
    69161,
    69257,
    69258,
    70755,
    70757,
    70758
  );
  script_osvdb_id(
    87160,
    109500,
    110143,
    113719,
    113720,
    113721,
    115948,
    115949,
    115950
  );

  script_name(english:"IBM WebSphere Portal 8.0.0.x < 8.0.0.1 CF15 Multiple Vulnerabilities");
  script_summary(english:"Checks for the installed patch.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has web portal software installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Portal installed on the remote host is
8.0.0.x prior to 8.0.0.1 CF15. It is, therefore, affected by multiple
vulnerabilities :

  - A flaw exists in 'Apache Commons HttpClient' that allows
    a man-in-the-middle attacker to spoof SSL servers via a
    certificate with a subject that specifies a common name
    in a field that is not the CN field. (CVE-2012-6153)

  - A flaw exists in 'Apache HttpComponents' that allows a
    man-in-the-middle attacker to spoof SSL servers via a
    certificate with a subject that specifies a common name
    in a field that is not the CN field. (CVE-2014-3577)

  - An unspecified vulnerability exists that allows an
    authenticated attacker to execute arbitrary code on the
    system. (CVE-2014-4808)

  - A flaw exists due to improper recursion detection during
    entity expansion. A remote attacker, via a specially
    crafted XML document, can cause the system to crash,
    resulting in a denial of service. (CVE-2014-4814)

  - An information disclosure vulnerability exists that
    allows a remote attacker to identify whether or not a
    file exists based on the web server error codes.
    (CVE-2014-4821)

  - A cross-site scripting vulnerability exists in the
    'Preview' plugin in CKEditor, which allows a remote
    attacker to inject arbitrary data via unspecified
    vectors. (CVE-2014-5191)

  - A cross-site scripting vulnerability exists that allows
    an attacker to inject arbitrary web script or HTML via a
    specially crafted URL. (CVE-2014-6171)

  - A flaw exists when the Managed Pages setting is enabled
    that allows a remote, authenticated attacker to write to
    pages via an XML injection attack. (CVE-2014-6193)

  - A cross-site scripting vulnerability exists in the Blog
    Portlet, which allows an attacker to inject arbitrary
    data via a specially crafted URL. (CVE-2014-8902)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24034497#WP15");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Portal 8.0.0.1 Cumulative Fix 15 (CF15) or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_portal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("websphere_portal_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Portal");

  exit(0);
}

include("websphere_portal_version.inc");

websphere_portal_check_version(
  ranges:make_list("8.0.0.0, 8.0.0.1"),
  fix:"CF15",
  severity:SECURITY_WARNING,
  xss:TRUE
);
