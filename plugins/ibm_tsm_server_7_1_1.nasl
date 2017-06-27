#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80478);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/14 15:43:29 $");

  script_cve_id("CVE-2013-6747");
  script_bugtraq_id(65156);
  script_osvdb_id(102556);

  script_name(english:"IBM Tivoli Storage Manager Server 6.2 < 6.2.7 / 6.3 < 6.3.5 / 7.1 < 7.1.1 GSKit X.509 Certificate Chain DoS");
  script_summary(english:"Checks the version of IBM TSM.");

  script_set_attribute(attribute:"synopsis", value:
"The remote backup service is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Tivoli Storage Manager installed on the remote host
is affected by a denial of service vulnerability. A remote attacker
can exploit this issue via malformed X.509 certificate chain to cause
the host to become unresponsive.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21674824");
  script_set_attribute(attribute:"solution", value:
"Upgrade IBM Tivoli Storage Manager or apply the correct GSKit patch.
Alternatively, apply the workaround per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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
install = get_single_install(app_name:prod, port:port, exit_if_unknown_ver:TRUE);

# Install data
version = install["version"];

fix = NULL;

if (version =~ "^6\.2(\.|$)")
  fix = "6.2.7";

else if (version =~ "^6\.3(\.|$)")
  fix = "6.3.5";

else if (version =~ "^7\.1(\.|$)")
  fix = "7.1.1";

else
  audit(AUDIT_NOT_LISTEN, prod+" 6.2 / 6.3 / 7.1", port);

# See if SSL is on for the port we're checking
sslon = get_kb_item("Transports/TCP/"+port);
sslon = (sslon && sslon > ENCAPS_IP);

# Work around is to turn SSL off
if(!sslon && report_paranoia < 2) audit(AUDIT_LISTEN_NOT_VULN, prod, port);

if(ver_compare(ver:version,fix:fix,strict:FALSE) <  0)
{

  if(report_verbosity > 0)
  {
    report =
      '\n  Product           : ' + prod +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
      security_hole(port:port,extra:report);
  } else security_hole(port);
} else audit(AUDIT_LISTEN_NOT_VULN, prod, port);
