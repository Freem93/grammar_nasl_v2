#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85544);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/13 20:14:28 $");

  script_cve_id(
    "CVE-2015-4531",
    "CVE-2015-4532",
    "CVE-2015-4533",
    "CVE-2015-4534",
    "CVE-2015-4535"
  );
  script_bugtraq_id(
    76409,
    76410,
    76411,
    76413,
    76414
  );
  script_osvdb_id(
    126373,
    126374,
    126375,
    126376,
    126377
  );

  script_name(english:"EMC Documentum Content Server Multiple Vulnerabilities (ESA-2015-131)");
  script_summary(english:"Checks for the Documentum Content Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of EMC Documentum Content Server running on the remote
host is affected by multiple vulnerabilities :

  - A privilege escalation vulnerability exists due to
    improper authorization checks performed on subgroups
    within the dm_superusers group. An authenticated, remote
    attacker can exploit this to gain super-user privileges,
    thus allowing access to data or unauthorized actions on
    the Content Server. Note that the previous fix for this
    issue (CVE-2014-4622) was incomplete. (CVE-2015-4531)

  - A privilege escalation vulnerability exists due to
    improper authorization and object type checks performed
    during the handling of RPC commands that involve the
    dm_bp_transition method. An authenticated, remote
    attacker can exploit this, by using a crafted script,
    to gain elevated privileges, thus allowing unauthorized
    actions, such as the execution of arbitrary code. Note
    that the previous fix for this issue (CVE-2014-2514) was
    incomplete. (CVE-2015-4532)

  - A privilege escalation vulnerability exists due to
    improper authorization checks during the handling of
    custom scripts. An authenticated, remote attacker can
    exploit this to gain elevated privileges, thus allowing
    unauthorized actions on the Content Server. Note that
    the previous fix for this issue (CVE-2014-2513) was
    incomplete. (CVE-2015-4533)

  - A remote code execution vulnerability exists due to the
    Java Method Server (JMS) not properly validating digital
    signatures for query strings without the 'method_verb'
    parameter. An authenticated, remote attacker can exploit
    this, via a crafted digital signature for a query
    string, to execute arbitrary code in the JMS context,
    depending on what Java classes are present in the
    classloader. (CVE-2015-4534)

  - An information disclosure vulnerability exists due to
    a flaw in the Java Method Server (JMS) in how login
    tickets are logged in certain instances when the
    __debug_trace__ parameter is enabled. An authenticated,
    remote attacker with access to the logs can exploit this
    to gain access to super-user tickets. (CVE-2015-4535)");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2015/Aug/att-86/ESA-2015-131.txt");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:documentum_content_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"Windows");

  script_dependencies("emc_documentum_content_server_installed.nbin");
  script_require_keys("installed_sw/EMC Documentum Content Server");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("emc_documentum.inc");

app_name = DOC_APP_NAME;
install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);

fixes = make_nested_list(
  make_list("6.7SP1P32", DOC_NO_MIN),
  make_list("6.7SP2P25"),
  make_list("7.0P19"),
  make_list("7.1P16"),
  make_list("7.2P02")
);

documentum_check_and_report(install:install, fixes:fixes, severity:SECURITY_HOLE);
