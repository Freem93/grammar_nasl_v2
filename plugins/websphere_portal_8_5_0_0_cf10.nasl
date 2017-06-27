#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93027);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_cve_id(
    "CVE-2015-7472",
    "CVE-2016-0245",
    "CVE-2016-2925"
  );
  script_bugtraq_id(
    82548,
    83485,
    92180
  );
  script_osvdb_id(
    133977,
    135012,
    142244
  );
  script_xref(name:"IAVB", value:"2016-B-0135");

  script_name(english:"IBM WebSphere Portal 8.5.0.0 < 8.5.0.0 CF10 Multiple Vulnerabilities");
  script_summary(english:"Checks for the installed patch.");

  script_set_attribute(attribute:"synopsis", value:
"The web portal software installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Portal installed on the remote Windows
host is 8.5.0.0 prior to 8.5.0.0 CF10. It is, therefore, affected by
multiple vulnerabilities :

  - An unspecified flaw exists that is triggered when
    handling a specially crafted request. An
    unauthenticated, remote attacker can exploit this to
    inject arbitrary LDAP content and view, add, modify or
    delete information in the user repository.
    (CVE-2015-7472)

  - An XXE (XML external entity) injection vulnerability
    exists due to an incorrectly configured XML parser
    accepting XML external entities from an untrusted
    source. An unauthenticated, remote attacker can exploit
    this, via specially crafted XML data, to cause a denial
    of service condition or disclose sensitive information.
    (CVE-2016-0245)

  - A cross-site scripting (XSS) vulnerability exists due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (CVE-2016-2925)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24037786#CF10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Portal version 8.5.0.0 CF10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/02/02");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/18");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:ibm:websphere_portal");
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
  ranges:make_list("8.5.0.0, 8.5.0.0"),
  fix:"CF10",
  severity:SECURITY_WARNING,
  xss:TRUE
);
