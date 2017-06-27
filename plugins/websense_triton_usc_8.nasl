#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83739);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/05/22 14:14:42 $");

  script_cve_id(
    "CVE-2014-9711",
    "CVE-2015-2702",
    "CVE-2015-2703",
    "CVE-2015-2746",
    "CVE-2015-2748"
  );
  script_bugtraq_id(
    73233,
    73236,
    73240,
    73241,
    73242,
    73243,
    73345
  );
  script_osvdb_id(
    119801,
    119802,
    119804,
    119805,
    119806,
    119807,
    119808
  );

  script_name(english:"Websense TRITON 7.8 Multiple Vulnerabilities");
  script_summary(english:"Do a paranoid version check for Websense TRITON.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an information security application with
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Websense TRITON version 7.8.2 through
7.8.4. It is, therefore, potentially affected by multiple 
vulnerabilities :

  - Multiple cross-site scripting vulnerabilities exist in
    the Investigative Reports due to a failure to properly
    validate the input to the 'ReportName' parameter to the
    Explorer report scheduler and the input to the 'col'
    parameter to the Names and Anonymous summary report
    pages. A remote attacker can exploit these
    vulnerabilities to inject arbitrary script or HTML in
    the user's browser session. (CVE-2014-9711)

  - A stored cross-site scripting flaw exists due to a
    failure to validate input to the sender address field
    from an email when viewing audit log details. Websense
    TRITON is affected only if the Email Security component
    is installed. (CVE-2015-2702)

  - Multiple cross-site scripting vulnerabilities exist due
    to a failure to validate the input to the 'ws-encdata'
    parameter of the 'moreBlockInfo.cgi' script in the Data
    Security block page and the input to the 'admin_msg'
    parameter to the 'client-cert-import_wsoem.html' in the
    Content Gateway. A remote attacker can exploit these
    vulnerabilities to inject arbitrary script or HTML in
    the user's browser session. Websense TRITON is affected
    only if the Web Security component is installed.
    (CVE-2015-2703)

  - A command injection flaw exists due to a failure to
    validate the 'Destination' parameter of the
    CommandLineServlet of the Appliance Manager interface.
    An authenticated attacker can submit a specially crafted
    request to the servlet resulting in arbitrary commands
    being run as the root user on any V-Series appliances
    being managed by Websense TRITON. Note that the commands
    are executed on the appliance only and not the server
    that Websense TRITON is running on. (CVE-2015-2746)

  - Websense TRITON does not properly restrict access to
    files in the 'explorer_wse/' path. A remote attacker, by
    using a direct request to a Web Security incident report
    or the Explorer configuration (websense.ini) file, can
    thereby gain access to sensitive information. Websense
    TRITON is affected only if the Web Security component is
    installed. (CVE-2015-2748)");
  # https://www.securify.nl/advisory/SFY20140914/multiple_cross_site_scripting_vulnerabilities_in_websense_reporting.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3bff864f");
  # https://www.securify.nl/advisory/SFY20140906/command_injection_vulnerability_in_network_diagnostics_tool_of_websense_appliance_manager.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1605810b");
  # https://www.securify.nl/advisory/SFY20140916/error_messages_of_websense_content_gateway_are_vulnerable_to_cross_site_scripting.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f5915409");
  # https://www.securify.nl/advisory/SFY20140910/cross_site_scripting_vulnerability_in_websense_data_security_block_page.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b4f2a526");
  # https://www.securify.nl/advisory/SFY20140911/cross_site_scripting_vulnerability_in_websense_explorer_report_scheduler.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35904cd7");
  # https://www.securify.nl/advisory/SFY20140905/websense_email_security_vulnerable_to_persistent_cross_site_scripting_in_audit_log_details_view.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d81ea8fc");
  # http://www.websense.com/support/article/kbarticle/Vulnerabilities-resolved-in-TRITON-APX-Version-8-0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c46d757d");
  script_set_attribute(attribute:"solution", value:
"Some hotfixes have been released to address individual issues;
however, only updating to 8.0 resolves all the issues listed.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:websense:triton_ap_data");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:websense:triton_ap_email");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:websense:triton_ap_web");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:websense:triton_unified_security_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("websense_triton_usc_installed.nbin");
  script_require_keys("installed_sw/Websense TRITON", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app     = "Websense TRITON";
install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];

if(report_paranoia < 2)
  audit(AUDIT_PARANOID);

# Can only confirm 7.8.2 - 7.8.4 are affected by this set
if(ver_compare(ver:version, fix:"7.8.2", strict:FALSE) <= -1 ||
   ver_compare(ver:version, fix:"7.8.4", strict:FALSE) >=  1)
  audit(AUDIT_INST_PATH_NOT_VULN,app,version,path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

if(report_verbosity > 0)
{
  report = '\n  Path    : '+path+
           '\n  Version : '+version+
           '\n  Fixed   : 8.0.0'+
           '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
