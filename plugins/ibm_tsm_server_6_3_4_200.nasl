#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77120);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/16 14:02:51 $");

  script_cve_id("CVE-2013-0169");
  script_bugtraq_id(57778);
  script_osvdb_id(89848);

  script_name(english:"IBM Tivoli Storage Manager Server 6.3.x < 6.3.4.200 Information Disclosure");
  script_summary(english:"Checks the version of IBM TSM.");

  script_set_attribute(attribute:"synopsis", value:
"The remote backup service is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Tivoli Storage Manager installed on the remote host
is 6.3.x prior to 6.3.4.200. It is, therefore, affected by a
vulnerability that could allow a remote attacker to perform a
statistical timing attack known as 'Lucky Thirteen'.");
  # http://www-01.ibm.com/support/docview.wss?uid=swg21672363
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9986de60");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_tivoli_storage_manager_server_gskit_lucky_13_vulnerability_cve_2013_0169?lang=en_us
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?b7623c06");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Tivoli Storage Manager 6.3.4.200 or later or disable
SSL.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ibm_tsm_detect.nasl");
  script_require_keys("installed_sw/IBM Tivoli Storage Manager");
  script_require_ports("Services/tsm-agent");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

port    = get_service(svc:"tsm-agent",exit_on_fail:TRUE);
prod    = "IBM Tivoli Storage Manager";
get_install_count(app_name:prod, exit_if_zero:TRUE);
install = get_single_install(app_name:prod, port:port);

# Install data
version = install["version"];
# We are only concerned with 6.3 specifically
if(version !~ "^6\.3(\.|$)") audit(AUDIT_NOT_LISTEN, prod+" 6.3", port);

# See if SSL is on for the port we're checking
sslon = get_kb_item("Transports/TCP/"+port);
sslon = (sslon && sslon > ENCAPS_IP);

# Work around is to turn SSL off
if(!sslon && report_paranoia < 2) audit(AUDIT_LISTEN_NOT_VULN, prod, port);

fix = "6.3.4.200";
if(ver_compare(ver:version,fix:fix,strict:FALSE) <  0)
{

  if(report_verbosity > 0)
  {
    report =
      '\n  Product           : ' + prod +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
      security_note(port:port,extra:report);
  } else security_note(port);
} else audit(AUDIT_LISTEN_NOT_VULN, prod, port);
