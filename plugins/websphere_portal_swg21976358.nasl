#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89689);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/07/11 13:16:00 $");

  script_cve_id(
    "CVE-2015-7428",
    "CVE-2015-7455",
    "CVE-2015-7457",
    "CVE-2015-7491",
    "CVE-2016-0243",
    "CVE-2016-0244",
    "CVE-2016-0245"
  );
  script_osvdb_id(
    135006,
    135007,
    135008,
    135009,
    135010,
    135011,
    135012
  );

  script_name(english:"IBM WebSphere Portal Multiple Vulnerabilities (swg21976358)");
  script_summary(english:"Checks for the install patches.");

  script_set_attribute(attribute:"synopsis", value:
"The web portal software installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Portal installed on the remote host is version
6.1.0.x prior to 6.1.0.6 CF27 with patches, 6.1.5.x prior to 6.1.5.3
CF27 with patches, 7.0.0.x prior to 7.0.0.2 CF29 with patches, 8.0.0.x
prior to 8.0.0.1 CF20, or 8.5.0.0 prior to 8.5.0.0 CF09 with patches.
It is, therefore, affected by multiple vulnerabilities :

  - An open redirect vulnerability exists due to improper
    validation of input before returning it to the user. An
    attacker can exploit this, via a specially crafted link,
    to redirect a victim to an arbitrary website.
    (CVE-2015-7428)

  - A security bypass vulnerability exists due to insecure
    permissions. A remote attacker can exploit this to make
    changes to content items. (CVE-2015-7455)

  - Multiple unspecified cross-site scripting
    vulnerabilities exist due to improper validation of
    user-supplied input. A remote attacker can exploit this,
    via a specially crafted request, to execute arbitrary
    script code in a user's browser session. (CVE-2015-7457,
    CVE-2015-7491, CVE-2016-0243, CVE-2016-0244)

  - An XML External Entity (XXE) injection vulnerability
    exists due to an incorrectly configured XML parser
    accepting XML external entities from an untrusted
    source. A remote attacker can exploit this, via
    specially crafted XML data, to cause a denial of service
    condition or to disclose sensitive information.
    (CVE-2016-0245)");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg21976358");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate fixes per the vendor advisory.

  - For 6.1.0.x, upgrade to version 6.1.0.6 CF27 and apply
    interim fixes PI54088 and PI55327.

  - For 6.1.5.x, upgrade to version 6.1.5.3 CF27 and apply
    interim fixes PI54088 and PI55327.

  - For 7.0.0.x, upgrade to version 7.0.0.2 CF29 and apply
    interim fixes PI51234, PI55327, and PI54088.

  - For 8.0.0.x, upgrade to version 8.0.0.1 CF20.

  - For 8.5.0.x, upgrade to version 8.5.0 CF09 and apply
    interim fix PI56682.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/02/29");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/02/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:ibm:websphere_portal");
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
  checks:make_array(
    "8.5.0.0, 8.5.0.0, CF00-CF09", make_list('PI56682'),
    "8.0.0.0, 8.0.0.1", make_list("CF20"),
    "7.0.0.0, 7.0.0.2, CF00-CF29", make_list('PI51234', 'PI54088', 'PI55327'),
    "6.1.5.0, 6.1.5.3, CF00-CF27", make_list('PI54088', 'PI55327'),
    "6.1.0.0, 6.1.0.6, CF00-CF27", make_list('PI54088', 'PI55327')
 ),
  severity:SECURITY_WARNING,
  xss: TRUE
);
