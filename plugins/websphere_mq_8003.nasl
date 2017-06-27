#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99906);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/02 13:34:10 $");

  script_cve_id(
    "CVE-2015-1957",
    "CVE-2015-1967"
  );
  script_bugtraq_id(75540);
  script_osvdb_id(
    123584,
    123585
  );
  script_name(english:"IBM MQ 8.x < 8.0.0.3 Multiple Information Disclosure (credentialed check)");
  script_summary(english:"Checks the version of IBM MQ.");

  script_set_attribute(attribute:"synopsis", value:
"A message queuing application installed on the remote Windows host is
affected by multiple information disclosure vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM MQ (formerly IBM WebSphere MQ) 8.x installed on
the remote Windows host is missing fix pack 8.0.0.3 or later. It is,
therefore, affected by the following vulnerabilities :

  - A flaw exists in the Advanced Message Security policy
    when a JMS client application sends a message to the
    queue using this policy. Under certain circumstances,
    a cleartext duplicate copy of the message could be
    created outside the protected payload. An
    authenticated, remote attacker can exploit this, using
    man-in-the-middle techniques, to disclose sensitive
    information. (CVE-2015-1957)

  - A flaw exists in the MQ Explorer implementation in
    authentication credential handling due to the server
    transmitting authentication credentials in cleartext
    even if the server has been configured to protect
    passwords. An unauthenticated, remote attacker can
    can exploit this, using man-in-the-middle techniques,
    to disclose authentication credentials.
    (CVE-2015-1967)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21960506");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21960491");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg27043086#8003");
  script_set_attribute(attribute:"solution", value:
"Apply fix pack 8.0.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("websphere_mq_installed.nasl");
  script_require_keys("installed_sw/IBM WebSphere MQ", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"IBM WebSphere MQ", win_local:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:4);

vcf::ibm::verify_websphere_mq_component(app_info:app_info, required_flavor:'server', required_component:'explorer');

constraints = [
  { "min_version" : "8", "max_version" : "8.0.0.2", "fixed_version" : "8.0.0.3" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
