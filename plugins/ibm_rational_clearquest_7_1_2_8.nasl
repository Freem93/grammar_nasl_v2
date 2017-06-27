#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62786);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/03/12 15:08:55 $");

  script_cve_id("CVE-2012-2203");
  script_bugtraq_id(54743);
  script_osvdb_id(84473);

  script_name(english:"IBM Rational ClearQuest 7.1.x < 7.1.2.8 / 8.0.0.x < 8.0.0.4 GSKit Spoofing (credentialed check)");
  script_summary(english:"Checks the version of IBM Rational ClearQuest.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has software installed that is affected by a spoofing
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of IBM Rational ClearQuest 7.1.x prior
to 7.1.2.8 / 8.0.0.x prior to 8.0.0.4 installed. It is, therefore,
affected by a spoofing vulnerability related to the included Global
Security Kit (GSKit) and certificate objects.

The GSKit does not enforce file integrity of the PKCS #12 files it
uses and is vulnerable to SSL server spoofing because the insertion
of arbitrary CA certificates is possible.

Note that deployments not using LDAP are not affected and that PKCS
#12 is not the default format used by ClearQuest."
  );
  # Security bulletin
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21612036");
  # Fix packs availability notice
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21612033");

  script_set_attribute(attribute:"solution", value:"Upgrade to IBM Rational ClearQuest 7.1.2.8 / 8.0.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rational_clearquest");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies('ibm_rational_clearquest_installed.nasl');
  script_require_keys('installed_sw/IBM Rational ClearQuest', "Settings/ParanoidReport");
 
  exit(0);
}

include('ibm_rational_clearquest_version.inc');

rational_clearquest_check_version(
  fixes:make_nested_list(
    make_array("Min", "7.1.0.0", "Fix UI", "7.1.2.8", "Fix", "7.1208.0.124"),
    make_array("Min", "8.0.0.0", "Fix UI", "8.0.0.4", "Fix", "8.4.0.681")),
  severity:SECURITY_WARNING,
  paranoid:TRUE #only affects CQ installs using LDAP and PKCS #12 must be used
);
