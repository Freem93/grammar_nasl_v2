#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93075);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_cve_id("CVE-2015-7447", "CVE-2015-7472");
  script_bugtraq_id(79511, 82548);
  script_osvdb_id(131953, 133977);

  script_name(english:"IBM WebSphere Portal 8.0.0.x < 8.0.0.1 CF19 PI51395 and PI53426 Multiple Vulnerabilities");
  script_summary(english:"Checks for the installed patch.");

  script_set_attribute(attribute:"synopsis", value:
"The web portal software installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Portal installed on the remote host is
8.0.0.x prior to 8.0.0.1 CF19 with interim fixes PI51395 and PI53426.
It is, therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists in the
    Portal AccessControl REST API that allows an
    unauthenticated, remote attacker to bypass access
    control lists and disclose sensitive configuration
    information. (CVE-2015-7447)

  - An unspecified flaw exists when handling a specially
    crafted request that allows an unauthenticated, remote
    attacker to inject LDAP content and view, add, modify or
    delete information in the user repository.
    (CVE-2015-7472)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21972736");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21973152");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Portal version 8.0.0.1 CF19 with interim
fixes PI51395 and PI53426. Alternatively, upgrade to version 8.0.0.1
CF20.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/12/15");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/23");

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

# Eliminate false positives due to one of the fix paths being
#  CF19 with interim fixes PI53426 and PI51395.
websphere_portal_check_version(
    checks:make_array(
          "8.0.0.0, 8.0.0.1, CF19", make_list('PI53426, PI51395')
      ),
      severity:SECURITY_WARNING
    );
