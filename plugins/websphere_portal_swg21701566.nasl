#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83055);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/07/12 04:39:12 $");

  script_cve_id("CVE-2015-1886", "CVE-2015-1908");
  script_bugtraq_id(74216, 74218);
  script_osvdb_id(121027, 121028);

  script_name(english:"IBM WebSphere Portal Multiple Vulnerabilities (PI37356, PI37661)");
  script_summary(english:"Checks for the installed patches.");

  script_set_attribute(attribute:"synopsis", value:
"The web portal software installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Portal installed on the remote host is version
6.1.0.x prior to 6.1.0.6 CF27, 6.1.5.x prior to 6.1.5.3 CF27, 7.0.0.x
prior to 7.0.0.2 CF29, 8.0.0.x prior to 8.0.0.1 CF16, or 8.5.0.0 prior
to 8.5.0.0 CF05. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified flaw exists due to improper validation of
    user-supplied input. A remote attacker, using specially
    crafted requests, can exploit this to cause a denial of
    service by consuming all memory resources. Note that
    this only affects hosts in which the 'Remote Document
    Conversion Service' is enabled. (CVE-2015-1886, PI37356)

  - An unspecified cross-site scripting vulnerability exists
    due to improper validation of user-supplied input. A
    remote attacker, using a specially crafted URL, can
    exploit this to execute code in a victim's web browser
    within the security context of the hosted site, possibly
    resulting in access to the cookie-based authentication
    credentials. (CVE-2015-1908, PI37661)");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21701566");
  script_set_attribute(attribute:"solution", value:
"Upgrade IBM WebSphere Portal as noted in the referenced IBM advisory.

  - Versions 6.1.0.x should upgrade to 6.1.0.6 CF27 and then
    apply interim fixes PI37356 and PI37661.

  - Versions 6.1.5.x should upgrade to 6.1.5.3 CF27 and then
    apply interim fixes PI37356 and PI37661.

  - Versions 7.0.0.x should upgrade to 7.0.0.2 CF29 and then
    apply interim fixes PI37356 and PI37661.

  - Versions 8.0.0.x should upgrade to 8.0.0.1 CF16.

  - Versions 8.5.0.x should upgrade to 8.5.0.0 CF05 and then
    apply interim fixes PI37356 and PI37661.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/24");

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

fixes = make_list("PI37356", "PI37661");

websphere_portal_check_version(
  checks:make_array(
    "8.5.0.0, 8.5.0.0, CF05", fixes,
    "8.0.0.0, 8.0.0.1, CF16", fixes,
    "7.0.0.0, 7.0.0.2, CF29", fixes,
    "6.1.5.0, 6.1.5.3, CF27", fixes,
    "6.1.0.0, 6.1.0.6, CF27", fixes
 ),
  severity:SECURITY_WARNING,
  xss: TRUE
);
