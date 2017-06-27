#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77119);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/16 14:02:51 $");

  script_cve_id("CVE-2012-2191");
  script_bugtraq_id(54743);
  script_osvdb_id(84474);

  script_name(english:"IBM Tivoli Storage Manager Server 6.3.x < 6.3.4.0 DoS");
  script_summary(english:"Checks the version of IBM TSM.");

  script_set_attribute(attribute:"synopsis", value:
"The remote backup service is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Tivoli Storage Manager installed on the remote host
is 6.3.x prior to 6.3.4.0. It is, therefore, affected by a
vulnerability that could allow a remote attacker to cause a denial of
service via specially crafted values in the TLS Record Layer.");
  #http://www-01.ibm.com/support/docview.wss?uid=swg21672362
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?004af981");
  #https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_tivoli_storage_manager_server_gskit_encrypted_record_length_vulnerability_cve_2012_2191?lang=en_u
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?756252bb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Tivoli Storage Manager 6.3.4.0 or later, disable SSL,
or use a stream cipher such as RC4.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ibm_tsm_detect.nasl");
  script_require_keys("installed_sw/IBM Tivoli Storage Manager","Settings/ParanoidReport");
  script_require_ports("Services/tsm-agent");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

# They could be using a non-vulnerable cipher suite
if (report_paranoia < 2) audit(AUDIT_PARANOID);

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

fix = "6.3.4.0";
if(ver_compare(ver:version,fix:fix,strict:FALSE) < 0)
{
  if(report_verbosity > 0)
  {
    report =
      '\n  Product           : ' + prod +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
      security_warning(port:port,extra:report);
  } else security_warning(port);
} else audit(AUDIT_LISTEN_NOT_VULN, prod, port);
